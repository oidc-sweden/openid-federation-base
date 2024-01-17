package se.swedenconnect.oidcfed.commons.data.endpoints;

import static org.junit.jupiter.api.Assertions.*;

import java.sql.Date;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.oidcfed.commons.testdata.TestCredentials;
import se.swedenconnect.oidcfed.commons.utils.OidcUtils;

/**
 * Tests for Client Assertions
 */
@Slf4j
class ClientAssertionTest {

  @Test
  void testClientAssertions() throws Exception {

    log.info("Default client assertion creation");
    logClientAssertion(ClientAssertion.builder()
      .subject("https://example.com/subject")
      .audience("https://example.com/trust-mark-issuer")
      .build(TestCredentials.p256JwtCredential, null));

    log.info("Explicit time client assertion creation");
    logClientAssertion(ClientAssertion.builder()
      .subject("https://example.com/subject")
      .audience("https://example.com/trust-mark-issuer")
      .issueTime(Date.from(Instant.now().minusSeconds(10)))
      .expirationTime(java.util.Date.from(Instant.now().plusSeconds(20)))
      .build(TestCredentials.p256JwtCredential, null));

    log.info("Separate issuer");
    ClientAssertion separateIssuerCa = ClientAssertion.builder()
      .subject("https://example.com/subject")
      .issuer("https://example.com/issuer")
      .audience("https://example.com/trust-mark-issuer")
      .build(TestCredentials.p256JwtCredential, null);
    logClientAssertion(separateIssuerCa);
    assertEquals("https://example.com/issuer", separateIssuerCa.getIssuer());

    log.info("No audience test throws expected exception: {}",
      assertThrows(NullPointerException.class, () -> {
        ClientAssertion.builder()
          .subject("subject")
          .build(TestCredentials.p256JwtCredential,null);
      }).toString());

    log.info("No subject test throws expected exception: {}",
      assertThrows(NullPointerException.class, () -> {
        ClientAssertion.builder()
          .audience(List.of("Audience"))
          .build(TestCredentials.p256JwtCredential,null);
      }).toString());
  }

  void logClientAssertion(ClientAssertion clientAssertion) throws Exception{
    log.info("Client assertion:\n{}", clientAssertion.getClientAssertionJwt().serialize());

    log.info("Client assertion header:\n{}",
      OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
        .writeValueAsString(clientAssertion.getClientAssertionJwt().getHeader().toJSONObject()));

    log.info("Client assertion payload:\n{}",
      OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
        .writeValueAsString(clientAssertion.getClientAssertionJwt().getPayload().toJSONObject()));
  }

}