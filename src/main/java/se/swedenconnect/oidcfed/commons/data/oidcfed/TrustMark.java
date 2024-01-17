package se.swedenconnect.oidcfed.commons.data.oidcfed;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import lombok.Getter;
import se.swedenconnect.oidcfed.commons.security.JWTSigningCredential;
import se.swedenconnect.oidcfed.commons.utils.OidcUtils;

/**
 * Main data class holding data about a Trust Mark
 */
public class TrustMark {

  /** The JWT header typ value of Trust Marks */
  public static final JOSEObjectType TYPE = new JOSEObjectType("trust-mark+jwt");

  /**
   * Private constructor for the builder
   */
  private TrustMark() {
  }

  /**
   * Get instance of Trust Mark from Signed JWT
   *
   * @param signedJWT
   * @throws ParseException
   * @throws JsonProcessingException
   */
  public TrustMark(SignedJWT signedJWT) throws ParseException, JsonProcessingException {
    this.signedJWT = signedJWT;
    JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
    this.issuer = claimsSet.getIssuer();
    this.subject = claimsSet.getSubject();
    this.issueTime = claimsSet.getIssueTime();
    this.expirationTime = claimsSet.getExpirationTime();
    this.id = (String) claimsSet.getClaim("id");
    this.logoUri = (String) claimsSet.getClaim("logo_uri");
    this.ref = (String) claimsSet.getClaim("ref");
    this.delegation = claimsSet.getClaim("delegation") != null
    ? SignedJWT.parse((String) claimsSet.getClaim("delegation"))
    : null;
    this.extensions = OidcUtils.getExtensionProperties(claimsSet.toJSONObject(), null);
  }

  // JWT claims

  @Getter
  private SignedJWT signedJWT;

  @Getter
  private String issuer;

  @Getter
  private String subject;

  @Getter
  private Date issueTime;

  @Getter
  private Date expirationTime;

  // Additional Trust Mark claims

  @Getter
  private String id;

  @Getter
  private String logoUri;

  @Getter
  private String ref;

  @Getter
  private SignedJWT delegation;

  @Getter
  Map<String, Object> extensions;

  /**
   * Get a Trust Mark builder
   *
   * @return
   */
  public static TrustMarkBuilder builder() {
    return new TrustMarkBuilder();
  }
  /**
   * Builder class for a signed EntityStatement.
   */
  public static class TrustMarkBuilder {

    private static final SecureRandom rng = new SecureRandom();
    private final TrustMark trustMark;

    private TrustMarkBuilder() {
      this.trustMark = new TrustMark();
    }

    public TrustMarkBuilder issuer (String issuer) {
      this.trustMark.issuer = issuer;
      return this;
    }
    public TrustMarkBuilder subject (String subject) {
      this.trustMark.subject = subject;
      return this;
    }

    public TrustMarkBuilder issueTime (Date issueTime) {
      this.trustMark.issueTime = issueTime;
      return this;
    }

    public TrustMarkBuilder expriationTime (Date expriationTime) {
      this.trustMark.expirationTime = expriationTime;
      return this;
    }

    public TrustMarkBuilder id (String id) {
      this.trustMark.id = id;
      return this;
    }

    public TrustMarkBuilder logoUri (String logoUri) {
      this.trustMark.logoUri = logoUri;
      return this;
    }

    public TrustMarkBuilder ref (String ref) {
      this.trustMark.ref = ref;
      return this;
    }

    public TrustMarkBuilder delegation (SignedJWT delegation) {
      this.trustMark.delegation = delegation;
      return this;
    }

    public TrustMarkBuilder claim(String name, Object value) {
      Map<String, Object> extension = Optional.ofNullable(trustMark.getExtensions()).orElse(new HashMap<>());
      extension.put(name, value);
      this.trustMark.extensions = extension;
      return this;
    }

    /**
     * Build a signed Trust Mark
     *
     * @param signingCredential signing credentials for signing
     * @param permittedAlgorithms permitted algorithms and null if all algorithms are premitted
     * @return signed Trust Mark
     * @throws JsonProcessingException error processing JSON data
     * @throws NoSuchAlgorithmException no such algorithm
     * @throws JOSEException JSON signing error
     */
    public TrustMark build(JWTSigningCredential signingCredential, List<JWSAlgorithm> permittedAlgorithms)
      throws JsonProcessingException, NoSuchAlgorithmException, JOSEException {

      JWSAlgorithm algorithm = signingCredential.getJwsAlgorithm(permittedAlgorithms);

      JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
        .issuer(trustMark.getIssuer())
        .subject(trustMark.getSubject())
        .jwtID(new BigInteger(128, rng).toString(16))
        .expirationTime(trustMark.getExpirationTime())
        .issueTime(trustMark.getIssueTime());

      String delegationParam = trustMark.getDelegation() != null
        ? trustMark.getDelegation().serialize()
        : null;

      addClaims("id", trustMark.id, claimsSetBuilder);
      addClaims("logo_uri", trustMark.logoUri, claimsSetBuilder);
      addClaims("ref", trustMark.ref, claimsSetBuilder);
      addClaims("delegation", delegationParam, claimsSetBuilder);
      addClaims(trustMark.getExtensions(), claimsSetBuilder);

      JWTClaimsSet claimsSet = claimsSetBuilder.build();

      // Verify that all required claims are present
      Objects.requireNonNull(claimsSet.getIssuer(), "Issuer must be present");
      Objects.requireNonNull(claimsSet.getSubject(), "Subject must be present");
      Objects.requireNonNull(claimsSet.getIssueTime(), "Issue time must be present");
      Objects.requireNonNull(claimsSet.getClaim("id"), "Trust Mark ID must be present");

      SignedJWT jwt = new SignedJWT(
        new JWSHeader.Builder(algorithm)
          .keyID(signingCredential.getKid())
          .type(TrustMark.TYPE)
          .build(),
        claimsSet);
      jwt.sign(signingCredential.getSigner());
      trustMark.signedJWT = jwt;
      return trustMark;
    }

    private void addClaims(String claimName, Object value, JWTClaimsSet.Builder claimsSetBuilder) {
      if (value == null){
        return;
      }
      claimsSetBuilder.claim(claimName, value);
    }

    private void addClaims(Map<String, Object> jsonObject, JWTClaimsSet.Builder claimsSetBuilder) {
      if (jsonObject == null || jsonObject.isEmpty()){
        return;
      }
      jsonObject.keySet().forEach(claim -> claimsSetBuilder.claim(claim, jsonObject.get(claim)));
    }
  }



}
