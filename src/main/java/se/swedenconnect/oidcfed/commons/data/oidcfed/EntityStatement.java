package se.swedenconnect.oidcfed.commons.data.oidcfed;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.oidcfed.commons.security.JWTSigningCredential;
import se.swedenconnect.oidcfed.commons.utils.OidcUtils;

/**
 * Main data class holding data about an entity statement
 */
public class EntityStatement {

  /** The JWT header typ value of Entity Statements */
  public static final JOSEObjectType TYPE = new JOSEObjectType("entity-statement+jwt");

  /**
   * Private constructor for the builder
   */
  private EntityStatement() {
  }

  public EntityStatement(SignedJWT signedJWT) throws ParseException, JsonProcessingException {
    this.signedJWT = signedJWT;
    JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
    this.issuer = claimsSet.getIssuer();
    this.subject = claimsSet.getSubject();
    this.issueTime = claimsSet.getIssueTime();
    this.expirationTime = claimsSet.getExpirationTime();
    this.objectMapper = OidcUtils.OBJECT_MAPPER;
    Map<String, Object> payloadJsonObject = signedJWT.getPayload().toJSONObject();
    this.definedParams = objectMapper.readValue(
      objectMapper.writeValueAsString(payloadJsonObject),
      EntityStatementDefinedParams.class
    );
    this.extensions = OidcUtils.getExtensionProperties(payloadJsonObject, this.definedParams);
  }

  @Setter private ObjectMapper objectMapper;

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

  EntityStatementDefinedParams definedParams;

  @Getter
  Map<String, Object> extensions;

  /*
   *  Getters for defined claims
   */

  public JWKSet getJwkSet() throws ParseException {
   return JWKSet.parse(this.definedParams.getJwkSet());
  }
  public List<String> getAuthorityHints(){
    return this.definedParams.getAuthorityHints();
  }
  public String getSourceEndpoint(){
    return this.definedParams.getSourceEndpoint();
  }
  public EntityMetadataInfoClaim getMetadata(){
    return this.definedParams.getMetadata();
  }
  public EntityMetadataInfoClaim getMetadataPolicy(){
    return this.definedParams.getMetadataPolicy();
  }
  public ConstraintsClaim getConstraints(){
    return this.definedParams.getConstraints();
  }
  public List<String> getCriticalClaims(){
    return this.definedParams.getCriticalClaims();
  }
  public List<String> getMetadataPolicyCriticalClaims(){
    return this.definedParams.getMetadataPolicyCriticalClaims();
  }
  public List<TrustMarkClaim> getTrustMarks(){
    return this.definedParams.getTrustMarks();
  }
  public Map<String, List<String>> getTrustMarkIssuers(){
    return this.definedParams.getTrustMarkIssuers();
  }
  public Map<String, TrustMarkOwner> getTrustMarkOwners(){
    return this.definedParams.getTrustMarkOwners();
  }

  public SubjectDataPublication getSubjectDataPublication() {
    return this.definedParams.getSubjectDataPublication();
  }

  public static EntityStatementBuilder builder() {
    return new EntityStatementBuilder(OidcUtils.OBJECT_MAPPER);
  }
  public static EntityStatementBuilder builder(ObjectMapper objectMapper) {
    return new EntityStatementBuilder(objectMapper);
  }
  /**
   * Builder class for a signed EntityStatement.
   */
  public static class EntityStatementBuilder{

    private static final SecureRandom rng = new SecureRandom();
    private final EntityStatement entityStatement;

    private EntityStatementBuilder(ObjectMapper objectMapper) {
      this.entityStatement = new EntityStatement();
      this.entityStatement.setObjectMapper(objectMapper);
    }

    public EntityStatementBuilder issuer (String issuer) {
      entityStatement.issuer = issuer;
      return this;
    }
    public EntityStatementBuilder subject (String subject) {
      entityStatement.subject = subject;
      return this;
    }

    public EntityStatementBuilder issueTime (Date issueTime) {
      entityStatement.issueTime = issueTime;
      return this;
    }

    public EntityStatementBuilder expriationTime (Date expriationTime) {
      entityStatement.expirationTime = expriationTime;
      return this;
    }

    public EntityStatementBuilder definedParams (EntityStatementDefinedParams definedParams) {
      entityStatement.definedParams = definedParams;
      return this;
    }

    public EntityStatementBuilder extensions (Map<String, Object> extensions) {
      entityStatement.extensions = extensions;
      return this;
    }

    public EntityStatement build(JWTSigningCredential signingCredential, List<JWSAlgorithm> permittedAlgorithms)
      throws JsonProcessingException, NoSuchAlgorithmException, JOSEException {

      if (entityStatement.definedParams == null) {
        entityStatement.definedParams = EntityStatementDefinedParams.builder().build();
      }

      Map<String, Object> definedParamsObject = entityStatement.objectMapper.readValue(
        entityStatement.objectMapper.writeValueAsString(entityStatement.definedParams), new TypeReference<>() {
        }
      );

      JWSAlgorithm algorithm = signingCredential.getJwsAlgorithm(permittedAlgorithms);

      JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
        .issuer(entityStatement.getIssuer())
        .subject(entityStatement.getSubject())
        .jwtID(new BigInteger(128, rng).toString(16))
        .expirationTime(entityStatement.getExpirationTime())
        .issueTime(entityStatement.getIssueTime());

      addClaims(definedParamsObject, claimsSetBuilder);
      addClaims(entityStatement.extensions, claimsSetBuilder);

      SignedJWT jwt = new SignedJWT(
        new JWSHeader.Builder(algorithm)
          .keyID(signingCredential.getKid())
          .type(EntityStatement.TYPE)
          .build(),
          claimsSetBuilder
          .build());
      jwt.sign(signingCredential.getSigner());
      entityStatement.signedJWT = jwt;
      return entityStatement;
    }

    private void addClaims(Map<String, Object> jsonObject, JWTClaimsSet.Builder claimsSetBuilder) {
      if (jsonObject == null || jsonObject.isEmpty()){
        return;
      }
      jsonObject.keySet().forEach(claim -> claimsSetBuilder.claim(claim, jsonObject.get(claim)));
    }
  }

}
