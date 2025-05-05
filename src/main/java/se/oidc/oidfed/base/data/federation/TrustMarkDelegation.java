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

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Objects;

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
  public TrustMarkDelegation(final SignedJWT signedJWT) throws ParseException {
    this.signedJWT = signedJWT;
    final JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
    this.issuer = claimsSet.getIssuer();
    this.subject = claimsSet.getSubject();
    this.issueTime = claimsSet.getIssueTime();
    this.expirationTime = claimsSet.getExpirationTime();
    this.trustMarkId = (String) claimsSet.getClaim("id");
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
  private String trustMarkId;

  @Getter
  private String ref;

  /**
   * Get a Trust Mark Delegation builder
   *
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

    public TrustMarkDelegationBuilder issuer(final String issuer) {
      this.trustMarkDelegation.issuer = issuer;
      return this;
    }

    public TrustMarkDelegationBuilder subject(final String subject) {
      this.trustMarkDelegation.subject = subject;
      return this;
    }

    public TrustMarkDelegationBuilder issueTime(final Date issueTime) {
      this.trustMarkDelegation.issueTime = issueTime;
      return this;
    }

    public TrustMarkDelegationBuilder expriationTime(final Date expriationTime) {
      this.trustMarkDelegation.expirationTime = expriationTime;
      return this;
    }

    public TrustMarkDelegationBuilder trustMarkId(final String trustMarkId) {
      this.trustMarkDelegation.trustMarkId = trustMarkId;
      return this;
    }

    public TrustMarkDelegationBuilder ref(final String ref) {
      this.trustMarkDelegation.ref = ref;
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
    public TrustMarkDelegation build(final JWTSigningCredential signingCredential,
        final List<JWSAlgorithm> permittedAlgorithms)
        throws JsonProcessingException, NoSuchAlgorithmException, JOSEException {

      final JWSAlgorithm algorithm = signingCredential.getJwsAlgorithm(permittedAlgorithms);

      final JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
          .issuer(this.trustMarkDelegation.getIssuer())
          .subject(this.trustMarkDelegation.getSubject())
          .jwtID(new BigInteger(128, rng).toString(16))
          .expirationTime(this.trustMarkDelegation.getExpirationTime())
          .issueTime(this.trustMarkDelegation.getIssueTime());

      this.addClaims("trust_mark_id", this.trustMarkDelegation.trustMarkId, claimsSetBuilder);
      this.addClaims("ref", this.trustMarkDelegation.ref, claimsSetBuilder);

      final JWTClaimsSet claimsSet = claimsSetBuilder.build();

      // Verify that all required claims are present
      Objects.requireNonNull(claimsSet.getIssuer(), "Issuer must be present");
      Objects.requireNonNull(claimsSet.getSubject(), "Subject must be present");
      Objects.requireNonNull(claimsSet.getIssueTime(), "Issue time must be present");
      Objects.requireNonNull(claimsSet.getClaim("trust_mark_id"), "Trust Mark ID must be present");

      final SignedJWT jwt = new SignedJWT(
          new JWSHeader.Builder(algorithm)
              .keyID(signingCredential.getKid())
              .type(TrustMarkDelegation.TYPE)
              .build(),
          claimsSet);
      jwt.sign(signingCredential.getSigner());
      this.trustMarkDelegation.signedJWT = jwt;
      return this.trustMarkDelegation;
    }

    private void addClaims(final String claimName, final Object value, final JWTClaimsSet.Builder claimsSetBuilder) {
      if (value == null) {
        return;
      }
      claimsSetBuilder.claim(claimName, value);
    }
  }

}
