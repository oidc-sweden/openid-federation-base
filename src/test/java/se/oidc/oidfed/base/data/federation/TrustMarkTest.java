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

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import se.oidc.oidfed.base.testdata.TestCredentials;
import se.oidc.oidfed.base.utils.OidcUtils;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Trust Mark tests
 */
@Slf4j
class TrustMarkTest {

  @Test
  void builderTest() throws Exception {

    final TrustMark trustMark = TrustMark.builder()
        .trustMarkId("http://example.com/trust_mark_id")
        .issuer("http://example.com/trust_mark_issuer")
        .subject("http://example.com/trust_mark_subject")
        .issueTime(new Date())
        .expriationTime(Date.from(Instant.now().plus(Duration.ofDays(30))))
        .logoUri("http://example.com/logo")
        .ref("http://example.com/information")
        .claim("organization_name", "Trust Mark issuer organization")
        .claim("organization_nme#sv", "Utfärdare av tillitsmärke AB")
        .delegation(TrustMarkDelegation.builder()
            .issuer("https://example.com/trust_mark_owner")
            .subject("http://example.com/trust_mark_issuer")
            .trustMarkId("http://example.com/trust_mark_id")
            .issueTime(Date.from(Instant.now().minus(Duration.ofDays(10))))
            .expriationTime(Date.from(Instant.now().plus(Duration.ofDays(30))))
            .build(TestCredentials.p256JwtCredential, null).getSignedJWT())
        .build(TestCredentials.p256JwtCredential, null);

    final SignedJWT trustMarkSignedJWT = trustMark.getSignedJWT();
    final Map<String, Object> headerJsonObject = trustMarkSignedJWT.getHeader().toJSONObject();
    final String headerJson =
        OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(headerJsonObject);
    log.info("Trust Mark header:\n{}", headerJson);

    final JWTClaimsSet claimsSet = trustMarkSignedJWT.getJWTClaimsSet();
    final String payloadJson = OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
        .writeValueAsString(claimsSet.toJSONObject());

    log.info("Trust Mark payload:\n{}", payloadJson);

    JSONAssert.assertEquals("""
        {
          "sub" : "http://example.com/trust_mark_subject",
          "ref" : "http://example.com/information",
          "logo_uri" : "http://example.com/logo",
          "iss" : "http://example.com/trust_mark_issuer",
          "trust_mark_id" : "http://example.com/trust_mark_id",
          "organization_name" : "Trust Mark issuer organization",
          "organization_nme#sv" : "Utfärdare av tillitsmärke AB"
        }""", payloadJson, false);

    assertTrue(claimsSet.getIssueTime().toInstant().minusMillis(1).isBefore(Instant.now()));
    assertTrue(claimsSet.getIssueTime().toInstant().plusSeconds(5).isAfter(Instant.now()));
    assertTrue(Instant.now().plusSeconds(29).isBefore(claimsSet.getExpirationTime().toInstant()));
    assertTrue(Instant.now().plus(Duration.ofDays(31)).isAfter(claimsSet.getExpirationTime().toInstant()));
    assertNotNull(claimsSet.getJWTID());
    assertTrue(claimsSet.getJWTID().length() > 30);
    assertEquals("trust-mark+jwt", trustMarkSignedJWT.getHeader().getType().getType());

    final SignedJWT parsedDelegation = SignedJWT.parse((String) claimsSet.getClaim("delegation"));
    final Map<String, Object> delegationHeaderJsonObject = parsedDelegation.getHeader().toJSONObject();
    final String delegationHeaderJson =
        OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(delegationHeaderJsonObject);
    log.info("Trust Mark Delegation header:\n{}", delegationHeaderJson);

    final JWTClaimsSet delegationClaimsSet = parsedDelegation.getJWTClaimsSet();
    final String delegationPayloadJson = OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
        .writeValueAsString(delegationClaimsSet.toJSONObject());

    log.info("Trust Mark Delegation payload:\n{}", delegationPayloadJson);

    JSONAssert.assertEquals("""
        {
          "sub" : "http://example.com/trust_mark_issuer",
          "iss" : "https://example.com/trust_mark_owner",
          "trust_mark_id" : "http://example.com/trust_mark_id"
        }
        """, delegationPayloadJson, false);

    assertTrue(delegationClaimsSet.getIssueTime().toInstant().minusMillis(1).isBefore(Instant.now()));
    assertTrue(Instant.now().minus(Duration.ofDays(11)).isBefore(delegationClaimsSet.getIssueTime().toInstant()));
    assertTrue(Instant.now().plusSeconds(29).isBefore(delegationClaimsSet.getExpirationTime().toInstant()));
    assertTrue(Instant.now().plus(Duration.ofDays(31)).isAfter(delegationClaimsSet.getExpirationTime().toInstant()));
    assertNotNull(delegationClaimsSet.getJWTID());
    assertTrue(delegationClaimsSet.getJWTID().length() > 30);
    assertEquals("trust-mark-delegation+jwt", parsedDelegation.getHeader().getType().getType());

  }

}
