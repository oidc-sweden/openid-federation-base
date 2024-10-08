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

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import se.oidc.oidfed.base.testdata.TestCredentials;
import se.oidc.oidfed.base.utils.OidcUtils;

import java.sql.Date;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for Client Assertions
 */
@Slf4j
class ClientAssertionTest {

  @Test
  void testClientAssertions() throws Exception {

    log.info("Default client assertion creation");
    this.logClientAssertion(ClientAssertion.builder()
        .subject("https://example.com/subject")
        .audience("https://example.com/trust-mark-issuer")
        .build(TestCredentials.p256JwtCredential, null));

    log.info("Explicit time client assertion creation");
    this.logClientAssertion(ClientAssertion.builder()
        .subject("https://example.com/subject")
        .audience("https://example.com/trust-mark-issuer")
        .issueTime(Date.from(Instant.now().minusSeconds(10)))
        .expirationTime(java.util.Date.from(Instant.now().plusSeconds(20)))
        .build(TestCredentials.p256JwtCredential, null));

    log.info("Separate issuer");
    final ClientAssertion separateIssuerCa = ClientAssertion.builder()
        .subject("https://example.com/subject")
        .issuer("https://example.com/issuer")
        .audience("https://example.com/trust-mark-issuer")
        .build(TestCredentials.p256JwtCredential, null);
    this.logClientAssertion(separateIssuerCa);
    assertEquals("https://example.com/issuer", separateIssuerCa.getIssuer());

    log.info("No audience test throws expected exception: {}",
        assertThrows(NullPointerException.class, () -> ClientAssertion.builder()
            .subject("subject")
            .build(TestCredentials.p256JwtCredential, null)).toString());

    log.info("No subject test throws expected exception: {}",
        assertThrows(NullPointerException.class, () -> ClientAssertion.builder()
            .audience(List.of("Audience"))
            .build(TestCredentials.p256JwtCredential, null)).toString());
  }

  void logClientAssertion(final ClientAssertion clientAssertion) throws Exception {
    log.info("Client assertion:\n{}", clientAssertion.getClientAssertionJwt().serialize());

    log.info("Client assertion header:\n{}",
        OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
            .writeValueAsString(clientAssertion.getClientAssertionJwt().getHeader().toJSONObject()));

    log.info("Client assertion payload:\n{}",
        OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
            .writeValueAsString(clientAssertion.getClientAssertionJwt().getPayload().toJSONObject()));
  }

}
