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
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import se.oidc.oidfed.base.data.endpoints.ResolveResponse;
import se.oidc.oidfed.base.testdata.TestCredentials;
import se.oidc.oidfed.base.testdata.TestMetadata;
import se.oidc.oidfed.base.utils.OidcUtils;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Resolve respone tests
 */
@Slf4j
class ResolveResponseTest {

  public static EntityStatement entityStatement;
  public static TrustMark trustMark;

  @BeforeAll
  static void init() throws Exception {

    entityStatement = EntityStatement.builder()
        .issuer("issuer")
        .issueTime(new Date())
        .subject("subject")
        .expriationTime(Date.from(Instant.now().plus(Duration.ofDays(10))))
        .build(TestCredentials.p256JwtCredential, null);

    trustMark = TrustMark.builder()
        .issuer("issuer")
        .issueTime(new Date())
        .subject("subject")
        .expriationTime(Date.from(Instant.now().plus(Duration.ofDays(10))))
        .trustMarkId("trust_mark_id")
        .build(TestCredentials.p256JwtCredential, null);

  }

  @Test
  void resolveResponseTest() throws Exception {

    final ResolveResponse resolveResponse = ResolveResponse.builder()
        .issuer("issuer")
        .issueTime(new Date())
        .subject("subject")
        .expriationTime(Date.from(Instant.now().plus(Duration.ofDays(10))))
        .metadata(TestMetadata.opMetadata)
        .trustMarks(List.of(new TrustMarkClaim(trustMark.getTrustMarkId(), trustMark.getSignedJWT().serialize())))
        .trustChain(List.of(entityStatement))
        .build();

    final SignedJWT signedResponse = resolveResponse.sign(TestCredentials.p256JwtCredential, null);

    final ResolveResponse parsedResponse = new ResolveResponse(signedResponse);

    final SignedJWT signedParsedResponse = parsedResponse.sign(TestCredentials.p256JwtCredential, null);

    final Map<String, Object> headerJsonObject = signedParsedResponse.getHeader().toJSONObject();
    final String headerJson =
        OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(headerJsonObject);
    log.info("Resolve response header:\n{}", headerJson);
    assertEquals(ResolveResponse.TYPE, signedParsedResponse.getHeader().getType());

    final JWTClaimsSet claimsSet = signedParsedResponse.getJWTClaimsSet();
    final String payloadJson = OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
        .writeValueAsString(claimsSet.toJSONObject());

    log.info("Resolve response payload:\n{}", payloadJson);

    JSONAssert.assertEquals(new JSONObject((Map<?,?>) TestMetadata.opMetadata),
        new JSONObject((Map<?, ?>) claimsSet.getClaim("metadata")),false
    );
    final JWTClaimsSet rrcs = signedResponse.getJWTClaimsSet();
    assertEquals(entityStatement.getSignedJWT().serialize(), ((List<?>) claimsSet.getClaim("trust_chain")).get(0));
    final Map<String, Object> trustMarkMap = (Map<String, Object>) ((List<?>) claimsSet.getClaim("trust_marks")).get(0);
    final TrustMarkClaim trustMarkClaim = OidcUtils.OBJECT_MAPPER.convertValue(trustMarkMap, TrustMarkClaim.class);
    assertEquals(trustMark.getSignedJWT().serialize(), trustMarkClaim.getTrustMark());
    assertEquals(trustMark.getSignedJWT().serialize(), parsedResponse.getTrustMarks().get(0).getTrustMark());
    assertEquals(rrcs.getIssueTime(), claimsSet.getIssueTime());
    assertEquals(rrcs.getIssuer(), claimsSet.getIssuer());
    assertEquals(rrcs.getSubject(), claimsSet.getSubject());
    assertEquals(rrcs.getExpirationTime(), claimsSet.getExpirationTime());
  }

}
