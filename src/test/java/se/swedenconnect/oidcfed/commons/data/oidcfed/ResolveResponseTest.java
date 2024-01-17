package se.swedenconnect.oidcfed.commons.data.oidcfed;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.json.JSONObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.oidcfed.commons.data.endpoints.ResolveResponse;
import se.swedenconnect.oidcfed.commons.data.metadata.OpMetadata;
import se.swedenconnect.oidcfed.commons.testdata.TestCredentials;
import se.swedenconnect.oidcfed.commons.utils.OidcUtils;

import org.skyscreamer.jsonassert.JSONAssert;

/**
 * Resolve respone tests
 */
@Slf4j
class ResolveResponseTest {

  public static OpMetadata opMetadata;
  public static EntityStatement entityStatement;
  public static TrustMark trustMark;

  @BeforeAll
  static void init() throws Exception {
    opMetadata = OpMetadata.builder()
      .issuer("issuer")
      .build();

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
      .id("trust_mark_id")
      .build(TestCredentials.p256JwtCredential, null);

  }

  @Test
  void resolveResponseTest() throws Exception {

    ResolveResponse resolveResponse = ResolveResponse.builder()
      .issuer("issuer")
      .issueTime(new Date())
      .subject("subject")
      .expriationTime(Date.from(Instant.now().plus(Duration.ofDays(10))))
      .metadata(opMetadata.toJsonObject())
      .trustMarks(List.of(trustMark.getSignedJWT()))
      .trustChain(List.of(entityStatement))
      .build();

    SignedJWT signedResponse = resolveResponse.sign(TestCredentials.p256JwtCredential, null);

    ResolveResponse parsedResponse = new ResolveResponse(signedResponse);

    SignedJWT signedParsedResponse = parsedResponse.sign(TestCredentials.p256JwtCredential, null);

    Map<String, Object> headerJsonObject = signedParsedResponse.getHeader().toJSONObject();
    String headerJson = OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(headerJsonObject);
    log.info("Resolve response header:\n{}", headerJson);
    assertEquals(ResolveResponse.TYPE, signedParsedResponse.getHeader().getType());

    JWTClaimsSet claimsSet = signedParsedResponse.getJWTClaimsSet();
    String payloadJson = OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
      .writeValueAsString(claimsSet.toJSONObject());

    log.info("Resolve response payload:\n{}", payloadJson);

    JSONAssert.assertEquals(opMetadata.toJson(false),
      new JSONObject((Map<?, ?>) claimsSet.getClaim("metadata")), true
    );
    JWTClaimsSet rrcs = signedResponse.getJWTClaimsSet();
    assertEquals(entityStatement.getSignedJWT().serialize(), ((List<?>)claimsSet.getClaim("trust_chain")).get(0));
    assertEquals(trustMark.getSignedJWT().serialize(), ((List<?>)claimsSet.getClaim("trust_marks")).get(0));
    assertEquals(rrcs.getIssueTime(), claimsSet.getIssueTime());
    assertEquals(rrcs.getIssuer(), claimsSet.getIssuer());
    assertEquals(rrcs.getSubject(), claimsSet.getSubject());
    assertEquals(rrcs.getExpirationTime(), claimsSet.getExpirationTime());
  }

}