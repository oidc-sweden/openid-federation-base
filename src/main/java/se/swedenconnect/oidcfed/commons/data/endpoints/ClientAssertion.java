package se.swedenconnect.oidcfed.commons.data.endpoints;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
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

/**
 * Class implementing the Client Assertions JWT
 */
public class ClientAssertion {

  private static final SecureRandom rng = new SecureRandom();

  /** The JWT header typ value of Client Assertions */
  public static final JOSEObjectType TYPE = new JOSEObjectType("JWT");

  /**
   * Private constructor for the builder
   */
  private ClientAssertion() {
  }

  public ClientAssertion(SignedJWT signedJWT) throws ParseException, JsonProcessingException {
    JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
    this.clientAssertionJwt = signedJWT;
    this.issuer = claimsSet.getIssuer();
    this.subject = claimsSet.getSubject();
    this.issueTime = claimsSet.getIssueTime();
    this.expirationTime = claimsSet.getExpirationTime();
    this.audience = claimsSet.getAudience();
  }

  @Getter SignedJWT clientAssertionJwt;

  @Getter private String issuer;

  @Getter private String subject;

  @Getter private Date issueTime;

  @Getter private Date expirationTime;

  @Getter private Object audience;

  private void create(JWTSigningCredential signingCredential, List<JWSAlgorithm> permittedAlgorithms)
    throws NoSuchAlgorithmException, JOSEException {

    Objects.requireNonNull(subject, "Subject must not be null");
    this.issuer = Optional.ofNullable(this.issuer).orElse(this.subject);
    this.issueTime = Optional.ofNullable(this.issueTime).orElse(new Date());
    Objects.requireNonNull(audience, "Audience must not be null");

    JWSAlgorithm algorithm = signingCredential.getJwsAlgorithm(permittedAlgorithms);

    JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
      .issuer(this.issuer)
      .subject(this.subject)
      .jwtID(new BigInteger(128, rng).toString(16))
      .expirationTime(this.expirationTime)
      .issueTime(this.issueTime);

    if (this.audience != null) {
      if (this.audience instanceof String) {
        claimsSetBuilder.audience((String) this.audience);
      }
      if (this.audience instanceof List<?>) {
        if (((List)this.audience).stream().allMatch(o -> o instanceof String)){
          claimsSetBuilder.audience((List<String>) this.audience);
        }
      }
    }

    if (claimsSetBuilder.getClaims().get("aud") == null) {
      throw new JOSEException("Audience is required");
    }

    SignedJWT jwt = new SignedJWT(
      new JWSHeader.Builder(algorithm)
        .keyID(signingCredential.getKid())
        .type(TYPE)
        .build(),
      claimsSetBuilder
        .build());
    jwt.sign(signingCredential.getSigner());
    this.clientAssertionJwt = jwt;
  }

  /**
   * Provides a builder for Client Assertions
   * @return builder
   */
  public static ClientAssertionBuilder builder() {
    return new ClientAssertionBuilder();
  }

  /**
   * Builder class for a signed EntityStatement.
   */
  public static class ClientAssertionBuilder {

    private final ClientAssertion clientAssertion;

    private ClientAssertionBuilder() {
      this.clientAssertion = new ClientAssertion();
    }

    /**
     * Sets the issuer if different from the subject. This parameter takes by default the value of the subject parameter.
     *
     * @param issuer issuer name if different from subject name
     * @return this builder
     */
    public ClientAssertionBuilder issuer (String issuer) {
      this.clientAssertion.issuer = issuer;
      return this;
    }

    /**
     * Sets the subject of the client assertion
     *
     * @param subject subject of client assertion
     * @return this builder
     */
    public ClientAssertionBuilder subject (String subject) {
      this.clientAssertion.subject = subject;
      return this;
    }

    /**
     * Sets issue time if different from current time.
     *
     * @param issueTime issue time
     * @return this builder
     */
    public ClientAssertionBuilder issueTime (Date issueTime) {
      this.clientAssertion.issueTime = issueTime;
      return this;
    }

    public ClientAssertionBuilder expirationTime (Date expriationTime) {
      clientAssertion.expirationTime = expriationTime;
      return this;
    }

    public ClientAssertionBuilder audience (String audience) {
      clientAssertion.audience = audience;
      return this;
    }

    public ClientAssertionBuilder audience (List<String> audience) {
      clientAssertion.audience = audience;
      return this;
    }

    public ClientAssertion build(JWTSigningCredential signingCredential, List<JWSAlgorithm> permittedAlgorithms)
      throws NoSuchAlgorithmException, JOSEException {
      clientAssertion.create(signingCredential, permittedAlgorithms);
      return clientAssertion;
    }
  }

}
