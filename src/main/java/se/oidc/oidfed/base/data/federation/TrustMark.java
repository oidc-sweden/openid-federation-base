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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.Getter;
import se.oidc.oidfed.base.security.JWTSigningCredential;
import se.oidc.oidfed.base.utils.OidcUtils;

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
   * @param signedJWT the signed JWT
   * @throws ParseException for parsing errors
   * @throws JsonProcessingException for JSON errors
   */
  public TrustMark(final SignedJWT signedJWT) throws ParseException, JsonProcessingException {
    this.signedJWT = signedJWT;
    final JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
    this.issuer = claimsSet.getIssuer();
    this.subject = claimsSet.getSubject();
    this.issueTime = claimsSet.getIssueTime();
    this.expirationTime = claimsSet.getExpirationTime();
    this.trustMarkId = (String) claimsSet.getClaim("id");
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
  private String trustMarkId;

  @Getter
  private String logoUri;

  @Getter
  private String ref;

  @Getter
  private SignedJWT delegation;

  @Getter
  Map<String, Object> extensions;

  /**
   * Get a Trust Mark builder.
   *
   * @return the builder
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

    public TrustMarkBuilder issuer(final String issuer) {
      this.trustMark.issuer = issuer;
      return this;
    }

    public TrustMarkBuilder subject(final String subject) {
      this.trustMark.subject = subject;
      return this;
    }

    public TrustMarkBuilder issueTime(final Date issueTime) {
      this.trustMark.issueTime = issueTime;
      return this;
    }

    public TrustMarkBuilder expriationTime(final Date expriationTime) {
      this.trustMark.expirationTime = expriationTime;
      return this;
    }

    public TrustMarkBuilder trustMarkId(final String trustMarkId) {
      this.trustMark.trustMarkId = trustMarkId;
      return this;
    }

    public TrustMarkBuilder logoUri(final String logoUri) {
      this.trustMark.logoUri = logoUri;
      return this;
    }

    public TrustMarkBuilder ref(final String ref) {
      this.trustMark.ref = ref;
      return this;
    }

    public TrustMarkBuilder delegation(final SignedJWT delegation) {
      this.trustMark.delegation = delegation;
      return this;
    }

    public TrustMarkBuilder claim(final String name, final Object value) {
      final Map<String, Object> extension = Optional.ofNullable(this.trustMark.getExtensions()).orElse(new HashMap<>());
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
    public TrustMark build(final JWTSigningCredential signingCredential, final List<JWSAlgorithm> permittedAlgorithms)
        throws JsonProcessingException, NoSuchAlgorithmException, JOSEException {

      final JWSAlgorithm algorithm = signingCredential.getJwsAlgorithm(permittedAlgorithms);

      final JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
          .issuer(this.trustMark.getIssuer())
          .subject(this.trustMark.getSubject())
          .jwtID(new BigInteger(128, rng).toString(16))
          .expirationTime(this.trustMark.getExpirationTime())
          .issueTime(this.trustMark.getIssueTime());

      final String delegationParam = this.trustMark.getDelegation() != null
          ? this.trustMark.getDelegation().serialize()
          : null;

      this.addClaims("trust_mark_id", this.trustMark.trustMarkId, claimsSetBuilder);
      this.addClaims("logo_uri", this.trustMark.logoUri, claimsSetBuilder);
      this.addClaims("ref", this.trustMark.ref, claimsSetBuilder);
      this.addClaims("delegation", delegationParam, claimsSetBuilder);
      this.addClaims(this.trustMark.getExtensions(), claimsSetBuilder);

      final JWTClaimsSet claimsSet = claimsSetBuilder.build();

      // Verify that all required claims are present
      Objects.requireNonNull(claimsSet.getIssuer(), "Issuer must be present");
      Objects.requireNonNull(claimsSet.getSubject(), "Subject must be present");
      Objects.requireNonNull(claimsSet.getIssueTime(), "Issue time must be present");
      Objects.requireNonNull(claimsSet.getClaim("trust_mark_id"), "Trust Mark ID must be present");

      final SignedJWT jwt = new SignedJWT(
          new JWSHeader.Builder(algorithm)
              .keyID(signingCredential.getKid())
              .type(TrustMark.TYPE)
              .build(),
          claimsSet);
      jwt.sign(signingCredential.getSigner());
      this.trustMark.signedJWT = jwt;
      return this.trustMark;
    }

    private void addClaims(final String claimName, final Object value, final JWTClaimsSet.Builder claimsSetBuilder) {
      if (value == null) {
        return;
      }
      claimsSetBuilder.claim(claimName, value);
    }

    private void addClaims(final Map<String, Object> jsonObject, final JWTClaimsSet.Builder claimsSetBuilder) {
      if (jsonObject == null || jsonObject.isEmpty()) {
        return;
      }
      jsonObject.keySet().forEach(claim -> claimsSetBuilder.claim(claim, jsonObject.get(claim)));
    }
  }

}
