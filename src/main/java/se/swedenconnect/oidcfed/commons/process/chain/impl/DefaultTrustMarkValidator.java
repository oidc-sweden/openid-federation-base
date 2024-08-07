package se.swedenconnect.oidcfed.commons.process.chain.impl;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.lang.NonNull;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.oidcfed.commons.data.oidcfed.EntityStatement;
import se.swedenconnect.oidcfed.commons.data.oidcfed.TrustMark;
import se.swedenconnect.oidcfed.commons.data.oidcfed.TrustMarkOwner;
import se.swedenconnect.oidcfed.commons.process.chain.ChainValidationException;
import se.swedenconnect.oidcfed.commons.process.chain.ChainValidationResult;
import se.swedenconnect.oidcfed.commons.process.chain.FederationChainValidator;
import se.swedenconnect.oidcfed.commons.process.chain.FederationPathBuilder;
import se.swedenconnect.oidcfed.commons.process.chain.PathBuildingException;
import se.swedenconnect.oidcfed.commons.process.chain.TrustMarkStatusException;
import se.swedenconnect.oidcfed.commons.process.chain.TrustMarkStatusResolver;
import se.swedenconnect.oidcfed.commons.process.chain.TrustMarkValidator;
import se.swedenconnect.oidcfed.commons.utils.OidcUtils;

/**
 * Default implementation of Trust Mark validator
 */
@Slf4j
@RequiredArgsConstructor
public class DefaultTrustMarkValidator implements TrustMarkValidator {

  private final FederationPathBuilder pathBuilder;
  private final TrustMarkStatusResolver trustMarkStatusResolver;
  private final FederationChainValidator chainValidator;

  @Override public List<TrustMark> validateTrustMarks(final @NonNull List<TrustMark> trustMarks,
    final @NonNull String subject, final @NonNull String trustAnchor) throws ChainValidationException {

    if (trustMarks.isEmpty()) {
      log.debug("No trust marks to validate");
      return List.of();
    }

    List<TrustMark> validatedList = new ArrayList<>();
    for (TrustMark trustMark : trustMarks) {

      try {
        String trustMarkIssuer = trustMark.getIssuer();
        List<EntityStatement> trustMarkChain = pathBuilder.buildPath(trustMarkIssuer, trustAnchor, true);
        if (trustMarkChain.isEmpty()) {
          log.debug("No validation path to trust mark issuer");
          continue;
        }
        ChainValidationResult validationResult = chainValidator.validate(trustMarkChain);

        // Check trust mark signature against validated leaf entity key set
        EntityStatement trustMarkIssuerStatement = validationResult.getValidatedChain()
          .get(validationResult.getValidatedChain().size() - 1);
        if (!OidcUtils.verifySignedJWT(trustMark.getSignedJWT(), trustMarkIssuerStatement.getJwkSet())) {
          log.debug("Trust mark signature validation failed. Skipping");
          continue;
        }
        // Check validity time
        OidcUtils.verifyValidityTime(trustMark.getSignedJWT());

        // Check that issuer is authorized by trust anchor
        EntityStatement trustAnchorStatement = trustMarkChain.get(0);
        Map<String, List<String>> trustMarkIssuerMap = Optional.ofNullable(trustAnchorStatement.getTrustMarkIssuers())
          .orElse(new HashMap<>());
        if (!trustMarkIssuerMap.containsKey(trustMark.getId())) {
          log.debug("Trust mark {} is not supported by Trust Anchor. Skipping", trustMark.getId());
          continue;
        }
        List<String> supportedIssuers = trustMarkIssuerMap.get(trustMark.getId());
        if (!supportedIssuers.isEmpty()) {
          if (!supportedIssuers.contains(trustMark.getIssuer())) {
            log.debug("Trust Mark issuer {} is not supported for trust mark {}. Skipping", trustMark.getIssuer(),
              trustMark.getId());
            continue;
          }
        }

        // Check trust mark delegation
        SignedJWT delegation = trustMark.getDelegation();
        if (delegation != null) {
          Map<String, TrustMarkOwner> trustMarkOwners = Optional.ofNullable(trustAnchorStatement.getTrustMarkOwners())
            .orElse(new HashMap<>());
          if (!trustMarkOwners.containsKey(trustMark.getId())) {
            log.debug(
              "No trust mark owner for the present delegation is present in the Trust Anchor statement. Skipping");
            continue;
          }
          // Find the trust mark owner for this trust mark ID
          TrustMarkOwner trustMarkOwner = trustMarkOwners.get(trustMark.getId());
          // Check that the trust mark owner subject is the issuer of the delegation JWT
          JWTClaimsSet claimsSet = delegation.getJWTClaimsSet();
          String delegationSubject = claimsSet.getSubject();
          String delegationIssuer = claimsSet.getIssuer();
          if (!trustMarkOwner.getSubject().equals(delegationIssuer)) {
            log.debug("Trust mark delegation issuer, does not match the expected trust mark owner. Skipping");
            continue;
          }
          //Check signature
          if (!OidcUtils.verifySignedJWT(delegation, trustMarkOwner.getJwkSet())){
            log.debug("Delegation signature validation failed. Skipping");
            continue;
          }
          OidcUtils.verifyValidityTime(delegation);
          // Check that the delegation is issued for the trust mark issuer
          if (!delegationSubject.equals(trustMark.getIssuer())) {
            log.debug("Delegation subject does not match trust mark issuer name. Skipping");
            continue;
          }
          log.debug("Trust mark delegation successfully verified");
        }
        // Finally. Verify trust mark status
        if (trustMarkStatusResolver.isStatusActive(trustMark.getId(), trustMark.getSubject(), trustMark.getIssuer())){
          validatedList.add(trustMark);
          log.debug("Trust Mark ID {} is valid", trustMark.getId());
        } else {
          log.debug("Trust Mark is revoked. Skipping");
        }
      }
      catch (PathBuildingException | TrustMarkStatusException | ParseException | NullPointerException |
             JOSEException e) {
        log.debug("Failed to validate trust mark: {}", e.getMessage());
      }

    }
    return validatedList;

  }

}
