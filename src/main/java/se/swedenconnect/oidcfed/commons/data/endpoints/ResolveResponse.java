package se.swedenconnect.oidcfed.commons.data.endpoints;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.oidcfed.commons.data.oidcfed.EntityStatement;
import se.swedenconnect.oidcfed.commons.data.oidcfed.TrustMarkClaim;
import se.swedenconnect.oidcfed.commons.security.JWTSigningCredential;
import se.swedenconnect.oidcfed.commons.utils.OidcUtils;

/**
 * Class implementing the Resolve Response
 */
public class ResolveResponse {

  private static final SecureRandom rng = new SecureRandom();

  /** The JWT header typ value of Resolve Responses */
  public static final JOSEObjectType TYPE = new JOSEObjectType("resolve-response+jwt");

  /**
   * Private constructor for the builder
   */
  private ResolveResponse() {
  }

  public ResolveResponse(SignedJWT signedJWT) throws ParseException, JsonProcessingException {
    JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
    this.issuer = claimsSet.getIssuer();
    this.subject = claimsSet.getSubject();
    this.issueTime = claimsSet.getIssueTime();
    this.expirationTime = claimsSet.getExpirationTime();
    this.metadata = (Map<String, Object>) claimsSet.getClaim("metadata");
    this.trustMarks = claimsSet.getClaim("trust_marks") == null
      ? null
      : OidcUtils.getOidcObjectMapper().convertValue(claimsSet.getClaim("trust_marks"), new TypeReference<>() {
    });
    this.trustChain = claimsSet.getClaim("trust_chain") == null
      ? null
      : ((List<String>) claimsSet.getClaim("trust_chain")).stream()
      .map(s -> {
        try {
          return new EntityStatement(SignedJWT.parse(s));
        }
        catch (ParseException | JsonProcessingException e) {
          throw new RuntimeException(e);
        }
      }).toList();
  }

  @Getter @Setter
  private String issuer;

  @Getter @Setter
  private String subject;

  @Getter @Setter
  private Date issueTime;

  @Getter @Setter
  private Date expirationTime;

  @Getter @Setter Map<String, Object> metadata;

  @Getter @Setter List<TrustMarkClaim> trustMarks;

  @Getter @Setter List<EntityStatement> trustChain;

  public SignedJWT sign(JWTSigningCredential signingCredential, List<JWSAlgorithm> permittedAlgorithms)
    throws NoSuchAlgorithmException, JOSEException {
    JWSAlgorithm algorithm = signingCredential.getJwsAlgorithm(permittedAlgorithms);

    JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
      .issuer(getIssuer())
      .subject(getSubject())
      .jwtID(new BigInteger(128, rng).toString(16))
      .expirationTime(getExpirationTime())
      .issueTime(getIssueTime());

    addClaim("metadata", getMetadata(), claimsSetBuilder);
    addClaim("trust_marks", this.trustMarks == null
        ? null
        : this.trustMarks,
      claimsSetBuilder);
    addClaim("trust_chain", this.trustChain == null
        ? null
        : this.trustChain.stream().map(entityStatement -> entityStatement.getSignedJWT().serialize()).toList(),
      claimsSetBuilder);

    SignedJWT jwt = new SignedJWT(
      new JWSHeader.Builder(algorithm)
        .keyID(signingCredential.getKid())
        .type(TYPE)
        .build(),
      claimsSetBuilder
        .build());
    jwt.sign(signingCredential.getSigner());
    return jwt;
  }

  private void addClaim(String claimName, Object value, JWTClaimsSet.Builder claimsSetBuilder) {
    if (value == null) {
      return;
    }
    claimsSetBuilder.claim(claimName, value);
  }


  /*
   *  Getters for defined claims
   */

  public static ResolveResponseBuilder builder() {
    return new ResolveResponseBuilder();
  }

  /**
   * Builder class for a signed EntityStatement.
   */
  public static class ResolveResponseBuilder {

    private final ResolveResponse resolveResponse;

    private ResolveResponseBuilder() {
      this.resolveResponse = new ResolveResponse();
    }

    public ResolveResponseBuilder issuer(String issuer) {
      this.resolveResponse.issuer = issuer;
      return this;
    }

    public ResolveResponseBuilder subject(String subject) {
      this.resolveResponse.subject = subject;
      return this;
    }

    public ResolveResponseBuilder issueTime(Date issueTime) {
      this.resolveResponse.issueTime = issueTime;
      return this;
    }

    public ResolveResponseBuilder expriationTime(Date expriationTime) {
      resolveResponse.expirationTime = expriationTime;
      return this;
    }

    public ResolveResponseBuilder metadata(Map<String, Object> metadata) {
      this.resolveResponse.metadata = metadata;
      return this;
    }

    public ResolveResponseBuilder trustMarks(List<TrustMarkClaim> trustMarks) {
      this.resolveResponse.trustMarks = trustMarks;
      return this;
    }

    public ResolveResponseBuilder trustChain(List<EntityStatement> trustChain) {
      this.resolveResponse.trustChain = trustChain;
      return this;
    }

    public ResolveResponse build() {
      return resolveResponse;
    }
  }

}
