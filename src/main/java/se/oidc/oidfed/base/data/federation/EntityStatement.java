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
package se.oidc.oidfed.base.data.federation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.Getter;
import lombok.Setter;
import se.oidc.oidfed.base.security.JWTSigningCredential;
import se.oidc.oidfed.base.utils.OidcUtils;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Main data class holding data about an entity statement
 */
public class EntityStatement {

  /** The JWT header typ value of Entity Statements */
  public static final JOSEObjectType TYPE = new JOSEObjectType("entity-statement+jwt");
  /**
   * The name of the claim holding an alternative location of the subject's Entity Configuration, defined by OpenID
   * Federation Entity Configuration Hosting 1.0.
   */
  public static final String EC_LOCATION_CLAIM_NAME = "ec_location";

  /**
   * The name of the claim holding the registration policies that were applied when registering the subject, defined
   * by OpenID Federation Registration Policy 1.0.
   */
  public static final String REGISTRATION_POLICY_CLAIM_NAME = "registration_policy";

  /**
   * Private constructor for the builder
   */
  private EntityStatement() {
  }

  public EntityStatement(final SignedJWT signedJWT) throws ParseException {
    this.signedJWT = signedJWT;
    final JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
    this.issuer = claimsSet.getIssuer();
    this.subject = claimsSet.getSubject();
    this.issueTime = claimsSet.getIssueTime();
    this.expirationTime = claimsSet.getExpirationTime();
    this.jsonMapper = OidcUtils.JSON_MAPPER;
    final Map<String, Object> payloadJsonObject = signedJWT.getPayload().toJSONObject();
    this.definedParams = this.jsonMapper.readValue(
        this.jsonMapper.writeValueAsString(payloadJsonObject),
        EntityStatementDefinedParams.class
    );
    this.extensions = OidcUtils.getExtensionProperties(payloadJsonObject, this.definedParams);
  }

  @Setter
  private JsonMapper jsonMapper;

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

  public List<String> getAuthorityHints() {
    return this.definedParams.getAuthorityHints();
  }

  public String getSourceEndpoint() {
    return this.definedParams.getSourceEndpoint();
  }

  public EntityMetadataInfoClaim getMetadata() {
    return this.definedParams.getMetadata();
  }

  public EntityMetadataInfoClaim getMetadataPolicy() {
    return this.definedParams.getMetadataPolicy();
  }

  public ConstraintsClaim getConstraints() {
    return this.definedParams.getConstraints();
  }

  public List<String> getCriticalClaims() {
    return this.definedParams.getCriticalClaims();
  }

  public List<String> getMetadataPolicyCriticalClaims() {
    return this.definedParams.getMetadataPolicyCriticalClaims();
  }

  public List<TrustMarkClaim> getTrustMarks() {
    return this.definedParams.getTrustMarks();
  }

  public Map<String, List<String>> getTrustMarkIssuers() {
    return this.definedParams.getTrustMarkIssuers();
  }

  public Map<String, TrustMarkOwner> getTrustMarkOwners() {
    return this.definedParams.getTrustMarkOwners();
  }

  public String getEcLocation() {
    return this.definedParams.getEcLocation();
  }

  public List<String> getRegistrationPolicy() {
    return this.definedParams.getRegistrationPolicy();
  }

  public static EntityStatementBuilder builder() {
    return new EntityStatementBuilder(OidcUtils.JSON_MAPPER);
  }

  public static EntityStatementBuilder builder(final JsonMapper jsonMapper) {
    return new EntityStatementBuilder(jsonMapper);
  }

  /**
   * Builder class for a signed EntityStatement.
   */
  public static class EntityStatementBuilder {

    private static final SecureRandom rng = new SecureRandom();
    private final EntityStatement entityStatement;

    private EntityStatementBuilder(final JsonMapper jsonMapper) {
      this.entityStatement = new EntityStatement();
      this.entityStatement.setJsonMapper(jsonMapper);
    }

    public EntityStatementBuilder issuer(final String issuer) {
      this.entityStatement.issuer = issuer;
      return this;
    }

    public EntityStatementBuilder subject(final String subject) {
      this.entityStatement.subject = subject;
      return this;
    }

    public EntityStatementBuilder issueTime(final Date issueTime) {
      this.entityStatement.issueTime = issueTime;
      return this;
    }

    public EntityStatementBuilder expriationTime(final Date expriationTime) {
      this.entityStatement.expirationTime = expriationTime;
      return this;
    }

    public EntityStatementBuilder definedParams(final EntityStatementDefinedParams definedParams) {
      this.entityStatement.definedParams = definedParams;
      return this;
    }

    public EntityStatementBuilder extensions(final Map<String, Object> extensions) {
      this.entityStatement.extensions = extensions;
      return this;
    }

    public EntityStatement build(final JWTSigningCredential signingCredential,
        final List<JWSAlgorithm> permittedAlgorithms)
        throws NoSuchAlgorithmException, JOSEException {

      if (this.entityStatement.definedParams == null) {
        this.entityStatement.definedParams = EntityStatementDefinedParams.builder().build();
      }

      final Map<String, Object> definedParamsObject = this.entityStatement.jsonMapper.readValue(
          this.entityStatement.jsonMapper.writeValueAsString(this.entityStatement.definedParams),
          new TypeReference<>() {
          }
      );

      final JWSAlgorithm algorithm = signingCredential.getJwsAlgorithm(permittedAlgorithms);

      final JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
          .issuer(this.entityStatement.getIssuer())
          .subject(this.entityStatement.getSubject())
          .jwtID(new BigInteger(128, rng).toString(16))
          .expirationTime(this.entityStatement.getExpirationTime())
          .issueTime(this.entityStatement.getIssueTime());

      this.addClaims(definedParamsObject, claimsSetBuilder);
      this.addClaims(this.entityStatement.extensions, claimsSetBuilder);

      final SignedJWT jwt = new SignedJWT(
          new JWSHeader.Builder(algorithm)
              .keyID(signingCredential.getKid())
              .type(EntityStatement.TYPE)
              .build(),
          claimsSetBuilder
              .build());
      jwt.sign(signingCredential.getSigner());
      this.entityStatement.signedJWT = jwt;
      return this.entityStatement;
    }

    private void addClaims(final Map<String, Object> jsonObject, final JWTClaimsSet.Builder claimsSetBuilder) {
      if (jsonObject == null || jsonObject.isEmpty()) {
        return;
      }
      jsonObject.keySet().forEach(claim -> claimsSetBuilder.claim(claim, jsonObject.get(claim)));
    }
  }

}
