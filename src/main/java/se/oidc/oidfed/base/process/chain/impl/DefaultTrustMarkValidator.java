/*
 * Copyright 2024 OIDC Sweden
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.oidc.oidfed.base.process.chain.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.Nonnull;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import se.oidc.oidfed.base.data.federation.EntityStatement;
import se.oidc.oidfed.base.data.federation.TrustMark;
import se.oidc.oidfed.base.data.federation.TrustMarkOwner;
import se.oidc.oidfed.base.process.chain.ChainValidationException;
import se.oidc.oidfed.base.process.chain.ChainValidationResult;
import se.oidc.oidfed.base.process.chain.FederationChainValidator;
import se.oidc.oidfed.base.process.chain.FederationPathBuilder;
import se.oidc.oidfed.base.process.chain.PathBuildingException;
import se.oidc.oidfed.base.process.chain.TrustMarkStatusException;
import se.oidc.oidfed.base.process.chain.TrustMarkStatusResolver;
import se.oidc.oidfed.base.process.chain.TrustMarkValidator;
import se.oidc.oidfed.base.utils.OidcUtils;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Default implementation of Trust Mark validator
 */
@Slf4j
@RequiredArgsConstructor
public class DefaultTrustMarkValidator implements TrustMarkValidator {

  private final FederationPathBuilder pathBuilder;
  private final TrustMarkStatusResolver trustMarkStatusResolver;
  private final FederationChainValidator chainValidator;

  @Override
  public List<TrustMark> validateTrustMarks(final @Nonnull List<TrustMark> trustMarks,
      final @NonNull String subject, final @NonNull String trustAnchor) throws ChainValidationException {

    if (trustMarks.isEmpty()) {
      log.debug("No trust marks to validate");
      return List.of();
    }

    final List<TrustMark> validatedList = new ArrayList<>();
    for (final TrustMark trustMark : trustMarks) {

      try {
        final String trustMarkIssuer = trustMark.getIssuer();
        final List<EntityStatement> trustMarkChain = this.pathBuilder.buildPath(trustMarkIssuer, trustAnchor, true);
        if (trustMarkChain.isEmpty()) {
          log.debug("No validation path to trust mark issuer");
          continue;
        }
        final ChainValidationResult validationResult = this.chainValidator.validate(trustMarkChain);

        // Check trust mark signature against validated leaf entity key set
        final EntityStatement trustMarkIssuerStatement = validationResult.getValidatedChain()
            .get(validationResult.getValidatedChain().size() - 1);
        if (!OidcUtils.verifySignedJWT(trustMark.getSignedJWT(), trustMarkIssuerStatement.getJwkSet())) {
          log.debug("Trust mark signature validation failed. Skipping");
          continue;
        }
        // Check validity time
        OidcUtils.verifyValidityTime(trustMark.getSignedJWT());

        // Check that issuer is authorized by trust anchor
        final EntityStatement trustAnchorStatement = trustMarkChain.get(0);
        final Map<String, List<String>> trustMarkIssuerMap =
            Optional.ofNullable(trustAnchorStatement.getTrustMarkIssuers())
                .orElse(new HashMap<>());
        if (!trustMarkIssuerMap.containsKey(trustMark.getTrustMarkId())) {
          log.debug("Trust mark {} is not supported by Trust Anchor. Skipping", trustMark.getTrustMarkId());
          continue;
        }
        final List<String> supportedIssuers = trustMarkIssuerMap.get(trustMark.getTrustMarkId());
        if (!supportedIssuers.isEmpty()) {
          if (!supportedIssuers.contains(trustMark.getIssuer())) {
            log.debug("Trust Mark issuer {} is not supported for trust mark {}. Skipping", trustMark.getIssuer(),
                trustMark.getTrustMarkId());
            continue;
          }
        }

        // Check trust mark delegation
        final SignedJWT delegation = trustMark.getDelegation();
        if (delegation != null) {
          final Map<String, TrustMarkOwner> trustMarkOwners =
              Optional.ofNullable(trustAnchorStatement.getTrustMarkOwners())
                  .orElse(new HashMap<>());
          if (!trustMarkOwners.containsKey(trustMark.getTrustMarkId())) {
            log.debug(
                "No trust mark owner for the present delegation is present in the Trust Anchor statement. Skipping");
            continue;
          }
          // Find the trust mark owner for this trust mark ID
          final TrustMarkOwner trustMarkOwner = trustMarkOwners.get(trustMark.getTrustMarkId());
          // Check that the trust mark owner subject is the issuer of the delegation JWT
          final JWTClaimsSet claimsSet = delegation.getJWTClaimsSet();
          final String delegationSubject = claimsSet.getSubject();
          final String delegationIssuer = claimsSet.getIssuer();
          if (!trustMarkOwner.getSubject().equals(delegationIssuer)) {
            log.debug("Trust mark delegation issuer, does not match the expected trust mark owner. Skipping");
            continue;
          }
          //Check signature
          if (!OidcUtils.verifySignedJWT(delegation, trustMarkOwner.getJwkSet())) {
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
        if (this.trustMarkStatusResolver.isStatusActive(trustMark.getTrustMarkId(), trustMark.getSubject(),
            trustMark.getIssuer())) {
          validatedList.add(trustMark);
          log.debug("Trust Mark ID {} is valid", trustMark.getTrustMarkId());
        }
        else {
          log.debug("Trust Mark is revoked. Skipping");
        }
      }
      catch (final PathBuildingException | TrustMarkStatusException | ParseException | NullPointerException |
          JOSEException e) {
        log.debug("Failed to validate trust mark: {}", e.getMessage());
      }

    }
    return validatedList;

  }

}
