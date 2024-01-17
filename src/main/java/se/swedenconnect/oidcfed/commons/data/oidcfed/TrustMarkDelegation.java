package se.swedenconnect.oidcfed.commons.data.oidcfed;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Objects;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import lombok.Getter;
import se.swedenconnect.oidcfed.commons.security.JWTSigningCredential;

/**
 * Main data class holding data about a Trust Mark Delegation
 */
public class TrustMarkDelegation {

  /** The JWT header typ value for Trust Mark delegations */
  public static final JOSEObjectType TYPE = new JOSEObjectType("trust-mark-delegation+jwt");

  /**
   * Private constructor for the builder
   */
  private TrustMarkDelegation() {
  }

  /**
   * Constructor creating a Trust Mark Delegation from a signed JWT
   *
   * @param signedJWT signed JWT Trust Mark Delegation
   * @throws ParseException error parsing signed JWT
   */
  public TrustMarkDelegation(SignedJWT signedJWT) throws ParseException {
    this.signedJWT = signedJWT;
    JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
    this.issuer = claimsSet.getIssuer();
    this.subject = claimsSet.getSubject();
    this.issueTime = claimsSet.getIssueTime();
    this.expirationTime = claimsSet.getExpirationTime();
    this.id = (String) claimsSet.getClaim("id");
    this.ref = (String) claimsSet.getClaim("ref");
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

  // Additional Trust Mark Delegation claims
  @Getter
  private String id;

  @Getter
  private String ref;

  /**
   * Get a Trust Mark Delegation builder
   * @return
   */
  public static TrustMarkDelegationBuilder builder() {
    return new TrustMarkDelegationBuilder();
  }

  /**
   * Builder class for a Trust Mark Delegation.
   */
  public static class TrustMarkDelegationBuilder {

    private static final SecureRandom rng = new SecureRandom();
    private final TrustMarkDelegation trustMarkDelegation;

    private TrustMarkDelegationBuilder() {
      this.trustMarkDelegation = new TrustMarkDelegation();
    }

    public TrustMarkDelegationBuilder issuer (String issuer) {
      trustMarkDelegation.issuer = issuer;
      return this;
    }
    public TrustMarkDelegationBuilder subject (String subject) {
      trustMarkDelegation.subject = subject;
      return this;
    }

    public TrustMarkDelegationBuilder issueTime (Date issueTime) {
      trustMarkDelegation.issueTime = issueTime;
      return this;
    }

    public TrustMarkDelegationBuilder expriationTime (Date expriationTime) {
      trustMarkDelegation.expirationTime = expriationTime;
      return this;
    }

    public TrustMarkDelegationBuilder id (String id) {
      trustMarkDelegation.id = id;
      return this;
    }

    public TrustMarkDelegationBuilder ref (String ref) {
      trustMarkDelegation.ref = ref;
      return this;
    }

    /**
     * Build a signed Trust Mark Delegation
     *
     * @param signingCredential signing credentials for signing
     * @param permittedAlgorithms permitted algorithms and null if all algorithms are premitted
     * @return signed Trust Mark
     * @throws JsonProcessingException error processing JSON data
     * @throws NoSuchAlgorithmException no such algorithm
     * @throws JOSEException JSON signing error
     */
    public TrustMarkDelegation build(JWTSigningCredential signingCredential, List<JWSAlgorithm> permittedAlgorithms)
      throws JsonProcessingException, NoSuchAlgorithmException, JOSEException {

      JWSAlgorithm algorithm = signingCredential.getJwsAlgorithm(permittedAlgorithms);

      JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
        .issuer(trustMarkDelegation.getIssuer())
        .subject(trustMarkDelegation.getSubject())
        .jwtID(new BigInteger(128, rng).toString(16))
        .expirationTime(trustMarkDelegation.getExpirationTime())
        .issueTime(trustMarkDelegation.getIssueTime());


      addClaims("id", trustMarkDelegation.id, claimsSetBuilder);
      addClaims("ref", trustMarkDelegation.ref, claimsSetBuilder);

      JWTClaimsSet claimsSet = claimsSetBuilder.build();

      // Verify that all required claims are present
      Objects.requireNonNull(claimsSet.getIssuer(), "Issuer must be present");
      Objects.requireNonNull(claimsSet.getSubject(), "Subject must be present");
      Objects.requireNonNull(claimsSet.getIssueTime(), "Issue time must be present");
      Objects.requireNonNull(claimsSet.getClaim("id"), "Trust Mark ID must be present");

      SignedJWT jwt = new SignedJWT(
        new JWSHeader.Builder(algorithm)
          .keyID(signingCredential.getKid())
          .type(TrustMarkDelegation.TYPE)
          .build(),
        claimsSet);
      jwt.sign(signingCredential.getSigner());
      trustMarkDelegation.signedJWT = jwt;
      return trustMarkDelegation;
    }

    private void addClaims(String claimName, Object value, JWTClaimsSet.Builder claimsSetBuilder) {
      if (value == null){
        return;
      }
      claimsSetBuilder.claim(claimName, value);
    }
  }

}
