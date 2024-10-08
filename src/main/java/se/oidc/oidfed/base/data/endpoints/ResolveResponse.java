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
package se.oidc.oidfed.base.data.endpoints;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.Getter;
import lombok.Setter;
import se.oidc.oidfed.base.data.federation.EntityStatement;
import se.oidc.oidfed.base.data.federation.TrustMarkClaim;
import se.oidc.oidfed.base.security.JWTSigningCredential;
import se.oidc.oidfed.base.utils.OidcUtils;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Map;

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

  public ResolveResponse(final SignedJWT signedJWT) throws ParseException {
    final JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
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
              catch (final ParseException | JsonProcessingException e) {
                throw new RuntimeException(e);
              }
            }).toList();
  }

  @Getter
  @Setter
  private String issuer;

  @Getter
  @Setter
  private String subject;

  @Getter
  @Setter
  private Date issueTime;

  @Getter
  @Setter
  private Date expirationTime;

  @Getter
  @Setter
  Map<String, Object> metadata;

  @Getter
  @Setter
  List<TrustMarkClaim> trustMarks;

  @Getter
  @Setter
  List<EntityStatement> trustChain;

  public SignedJWT sign(final JWTSigningCredential signingCredential, final List<JWSAlgorithm> permittedAlgorithms)
      throws NoSuchAlgorithmException, JOSEException {
    final JWSAlgorithm algorithm = signingCredential.getJwsAlgorithm(permittedAlgorithms);

    final JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
        .issuer(this.getIssuer())
        .subject(this.getSubject())
        .jwtID(new BigInteger(128, rng).toString(16))
        .expirationTime(this.getExpirationTime())
        .issueTime(this.getIssueTime());

    this.addClaim("metadata", this.getMetadata(), claimsSetBuilder);
    this.addClaim("trust_marks", this.trustMarks == null
            ? null
            : OidcUtils.OBJECT_MAPPER.convertValue(this.trustMarks, List.class),
        claimsSetBuilder);
    this.addClaim("trust_chain", this.trustChain == null
            ? null
            : this.trustChain.stream().map(entityStatement -> entityStatement.getSignedJWT().serialize()).toList(),
        claimsSetBuilder);

    final SignedJWT jwt = new SignedJWT(
        new JWSHeader.Builder(algorithm)
            .keyID(signingCredential.getKid())
            .type(TYPE)
            .build(),
        claimsSetBuilder
            .build());
    jwt.sign(signingCredential.getSigner());
    return jwt;
  }

  private void addClaim(final String claimName, final Object value, final JWTClaimsSet.Builder claimsSetBuilder) {
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

    public ResolveResponseBuilder issuer(final String issuer) {
      this.resolveResponse.issuer = issuer;
      return this;
    }

    public ResolveResponseBuilder subject(final String subject) {
      this.resolveResponse.subject = subject;
      return this;
    }

    public ResolveResponseBuilder issueTime(final Date issueTime) {
      this.resolveResponse.issueTime = issueTime;
      return this;
    }

    public ResolveResponseBuilder expriationTime(final Date expriationTime) {
      this.resolveResponse.expirationTime = expriationTime;
      return this;
    }

    public ResolveResponseBuilder metadata(final Map<String, Object> metadata) {
      this.resolveResponse.metadata = metadata;
      return this;
    }

    public ResolveResponseBuilder trustMarks(final List<TrustMarkClaim> trustMarks) {
      this.resolveResponse.trustMarks = trustMarks;
      return this;
    }

    public ResolveResponseBuilder trustChain(final List<EntityStatement> trustChain) {
      this.resolveResponse.trustChain = trustChain;
      return this;
    }

    public ResolveResponse build() {
      return this.resolveResponse;
    }
  }

}
