package se.swedenconnect.oidcfed.commons.process.chain.impl;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.jwk.JWKSet;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.oidcfed.commons.configuration.PolicyParameterFormats;
import se.swedenconnect.oidcfed.commons.data.metadata.FederationEndpointMetadata;
import se.swedenconnect.oidcfed.commons.data.oidcfed.EntityMetadataInfoClaim;
import se.swedenconnect.oidcfed.commons.data.oidcfed.EntityStatement;
import se.swedenconnect.oidcfed.commons.data.oidcfed.TrustMark;
import se.swedenconnect.oidcfed.commons.data.oidcfed.TrustMarkDelegation;
import se.swedenconnect.oidcfed.commons.data.oidcfed.TrustMarkOwner;
import se.swedenconnect.oidcfed.commons.process.chain.FederationChainValidator;
import se.swedenconnect.oidcfed.commons.process.chain.FederationPathBuilder;
import se.swedenconnect.oidcfed.commons.process.chain.PathBuildingException;
import se.swedenconnect.oidcfed.commons.process.chain.TrustMarkStatusException;
import se.swedenconnect.oidcfed.commons.process.chain.TrustMarkStatusResolver;
import se.swedenconnect.oidcfed.commons.process.chain.TrustMarkValidator;
import se.swedenconnect.oidcfed.commons.process.metadata.MetadataPolicySerializer;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyOperatorFactory;
import se.swedenconnect.oidcfed.commons.process.metadata.impl.DefaultPolicyOperatorFactory;
import se.swedenconnect.oidcfed.commons.process.metadata.impl.StandardMetadataPolicySerializer;
import se.swedenconnect.oidcfed.commons.testdata.TestCredentials;
import se.swedenconnect.oidcfed.commons.testdata.TestEntityStatements;
import se.swedenconnect.oidcfed.commons.utils.JWKUtils;
import se.swedenconnect.oidcfed.commons.utils.OidcUtils;

/**
 * Test for trust mark validator
 */
@Slf4j
class DefaultTrustMarkValidatorTest {

  static PolicyOperatorFactory policyOperatorFactory;
  static MetadataPolicySerializer serializer;

  static FederationChainValidator federationChainValidator;

  @BeforeAll
  static void init() {

    JWKSet t1JwkSet = TestCredentials.getJwkSet(TestCredentials.ta1.getCertificate());

    policyOperatorFactory = DefaultPolicyOperatorFactory.getInstance();
    serializer = new StandardMetadataPolicySerializer(policyOperatorFactory,
      Arrays.stream(PolicyParameterFormats.values())
        .collect(
          Collectors.toMap(PolicyParameterFormats::getParameterName, PolicyParameterFormats::toMetadataParameter))
    );

    federationChainValidator = new DefaultFederationChainValidator(t1JwkSet, serializer);

  }


  @Test
  void trustMarkTests() throws Exception {

    performTrustMarkTest("Default success test",
      List.of(TrustMark.builder()
          .id("https://example.com/trustMark-1")
          .issuer("https://example.com/ie2")
          .subject("https://example.com/op1")
          .issueTime(new Date())
          .expriationTime(Date.from(Instant.now().plusSeconds(120)))
          .delegation(TrustMarkDelegation.builder()
            .id("https://example.com/trustMark-1")
            .issuer("https://example.com/trust-mark-owner")
            .subject("https://example.com/ie2")
            .issueTime(new Date())
            .expriationTime(Date.from(Instant.now().plusSeconds(3600)))
            .build(TestCredentials.p256JwtCredential, null).getSignedJWT())
        .build(TestCredentials.ie2Sig, null)),
      "op1",
      List.of(
        TestEntityStatements.ta1_conf()
          .trustMarkIssuersMap(
            Collections.singletonMap("https://example.com/trustMark-1", List.of("https://example.com/ie2")))
          .trustMarkOwnerMap(
            Collections.singletonMap("https://example.com/trustMark-1", new TrustMarkOwner(
              "https://example.com/trust-mark-owner",
              new JWKSet(List.of(
                JWKUtils.getJwkWithKid(TestCredentials.p256Credential.getCertificate(), "test_p256", false)))
            ))
          ),
        TestEntityStatements.ta1_ie1_statement(),
        TestEntityStatements.ie1_ie2_statement(),
        TestEntityStatements.ie2_ie2_configuration()
      ),
      List.of("https://example.com/trustMark-1"),
      true, null
      );


/*    performTrustMarkTest("Default reduced TM Issuer chain",
      List.of(TrustMark.builder()
          .id("https://example.com/trustMark-1")
          .issuer("https://example.com/ie2")
          .subject("https://example.com/op1")
          .issueTime(new Date())
          .expriationTime(Date.from(Instant.now().plusSeconds(120)))
          .delegation(TrustMarkDelegation.builder()
            .id("https://example.com/trustMark-1")
            .issuer("https://example.com/trust-mark-owner")
            .subject("https://example.com/ie2")
            .issueTime(new Date())
            .expriationTime(Date.from(Instant.now().plusSeconds(3600)))
            .build(TestCredentials.p256JwtCredential, null).getSignedJWT())
        .build(TestCredentials.ie2Sig, null)),
      "op1",
      List.of(
        TestEntityStatements.ta1_conf()
          .trustMarkIssuersMap(
            Collections.singletonMap("https://example.com/trustMark-1", List.of("https://example.com/ie2")))
          .trustMarkOwnerMap(
            Collections.singletonMap("https://example.com/trustMark-1", new TrustMarkOwner(
              "https://example.com/trust-mark-owner",
              new JWKSet(List.of(
                JWKUtils.getJwkWithKid(TestCredentials.p256Credential.getCertificate(), "test_p256", false)))
            ))
          ),
        TestEntityStatements.ta1_ie1_statement(),
        TestEntityStatements.ie1_ie2_statement()
          .metadata(EntityMetadataInfoClaim.builder()
            .federationEntityMetadataObject(FederationEndpointMetadata.builder()
              .federationFetchEndpoint("https://example.com/fetchEndpoint")
              .federationListEndpoint("https://example.com/listEndpoint")
              .federationTrustMarkEndpoint("https://example.com/trustMarkEndpoint")
              .build().toJsonObject())
            .build())
          .noSubjectDataStorage(true)
      ),
      List.of("https://example.com/trustMark-1"),
      true, null
      );*/


    performTrustMarkTest("Bad Trust Mark delegation",
      List.of(TrustMark.builder()
          .id("https://example.com/trustMark-1")
          .issuer("https://example.com/ie2")
          .subject("https://example.com/op1")
          .issueTime(new Date())
          .expriationTime(Date.from(Instant.now().plusSeconds(120)))
          .delegation(TrustMarkDelegation.builder()
            .id("https://example.com/trustMark-1")
            .issuer("https://example.com/trust-mark-owner")
            .subject("https://example.com/ie1")
            .issueTime(new Date())
            .expriationTime(Date.from(Instant.now().plusSeconds(3600)))
            .build(TestCredentials.p256JwtCredential, null).getSignedJWT())
        .build(TestCredentials.ie2Sig, null)),
      "op1",
      List.of(
        TestEntityStatements.ta1_conf()
          .trustMarkIssuersMap(
            Collections.singletonMap("https://example.com/trustMark-1", List.of("https://example.com/ie2")))
          .trustMarkOwnerMap(
            Collections.singletonMap("https://example.com/trustMark-1", new TrustMarkOwner(
              "https://example.com/trust-mark-owner",
              new JWKSet(List.of(
                JWKUtils.getJwkWithKid(TestCredentials.p256Credential.getCertificate(), "test_p256", false)))
            ))
          ),
        TestEntityStatements.ta1_ie1_statement(),
        TestEntityStatements.ie1_ie2_statement(),
        TestEntityStatements.ie2_ie2_configuration()
//        TestEntityStatements.ie1_ie2_statement()
//          .metadata(EntityMetadataInfoClaim.builder()
//            .federationEntityMetadataObject(FederationEndpointMetadata.builder()
//              .federationFetchEndpoint("https://example.com/fetchEndpoint")
//              .federationListEndpoint("https://example.com/listEndpoint")
//              .federationTrustMarkEndpoint("https://example.com/trustMarkEndpoint")
//              .build().toJsonObject())
//            .build())
//          .noSubjectDataStorage(true)
      ),
      List.of(),
      true, null
      );

    performTrustMarkTest("Revoked Trust Mark",
      List.of(TrustMark.builder()
          .id("https://example.com/trustMark-1")
          .issuer("https://example.com/ie2")
          .subject("https://example.com/op1")
          .issueTime(new Date())
          .expriationTime(Date.from(Instant.now().plusSeconds(120)))
        .build(TestCredentials.ie2Sig, null)),
      "op1",
      List.of(
        TestEntityStatements.ta1_conf()
          .trustMarkIssuersMap(
            Collections.singletonMap("https://example.com/trustMark-1", List.of("https://example.com/ie2"))),
        TestEntityStatements.ta1_ie1_statement(),
        TestEntityStatements.ie1_ie2_statement(),
        TestEntityStatements.ie2_ie2_configuration()
      ),
      List.of(),
      false, null
      );

    performTrustMarkTest("Wrong trust mark signing key",
      List.of(TrustMark.builder()
          .id("https://example.com/trustMark-1")
          .issuer("https://example.com/ie2")
          .subject("https://example.com/op1")
          .issueTime(new Date())
          .expriationTime(Date.from(Instant.now().plusSeconds(120)))
        .build(TestCredentials.rsa3072JwtCredential, null)),
      "op1",
      List.of(
        TestEntityStatements.ta1_conf()
          .trustMarkIssuersMap(
            Collections.singletonMap("https://example.com/trustMark-1", List.of("https://example.com/ie2"))),
        TestEntityStatements.ta1_ie1_statement(),
        TestEntityStatements.ie1_ie2_statement(),
        TestEntityStatements.ie2_ie2_configuration()
      ),
      List.of(),
      true, null
      );
  }


  void performTrustMarkTest(String message, List<TrustMark> trustMarks, String subjectId,
    List<TestEntityStatements.EsData.EsDataBuilder> builderChain, List<String> expected, boolean status,
    Class<? extends Exception> exceptionClass) throws Exception {
    log.info("Entity Statement chain validation test: " + message);

    String subject = "https://example.com/" + subjectId;
    String trustAnchorName = "https://example.com/ta1";

    if (exceptionClass != null) {
      Exception exception = assertThrows(exceptionClass, () -> {

        List<EntityStatement> tmiChain = builderChain.stream()
          .map(esDataBuilder -> TestEntityStatements.getEntityStatement(esDataBuilder.build()))
          .toList();
        TrustMarkValidator trustMarkValidator = getTrustMarkValidator(tmiChain, status);
        trustMarkValidator.validateTrustMarks(trustMarks, subject, trustAnchorName);

      });
      log.info("Caught expected exception {} with message: {}\n", exception.getClass().getSimpleName(),
        exception.getMessage());
      exception.printStackTrace();
      return;
    }

    List<EntityStatement> trustMarkIssuerChain = builderChain.stream()
      .map(esDataBuilder -> TestEntityStatements.getEntityStatement(esDataBuilder.build()))
      .toList();
    log.info("Validated chain");
    for (EntityStatement entityStatement : trustMarkIssuerChain) {
      logEntityStatementInfo(entityStatement);
    }
    TrustMarkValidator trustMarkValidator = getTrustMarkValidator(trustMarkIssuerChain, status);
    List<TrustMark> validatedTrustMarks = trustMarkValidator.validateTrustMarks(trustMarks, subject, trustAnchorName);
    for (String trustMarkId : expected) {
      assertTrue(validatedTrustMarks.stream().anyMatch(trustMark -> trustMarkId.equals(trustMark.getId())));
    }
    assertEquals(expected.size(), validatedTrustMarks.size());
    log.info("Found expected valid trust marks: {}\n", expected);
  }

  TrustMarkValidator getTrustMarkValidator(List<EntityStatement> chain, boolean status) {

    return    new DefaultTrustMarkValidator(
      new FederationPathBuilder() {
      @Override public List<EntityStatement> buildPath(String entityIdentifier, String trustAnchor)
        throws PathBuildingException {
        return chain;
      }
    },
    new TrustMarkStatusResolver() {
      @Override public boolean isStatusActive(String trustMarkId, String subject, String issuer)
        throws TrustMarkStatusException {
        return status;
      }
    }, federationChainValidator
    );
  }

  private void logEntityStatementInfo(EntityStatement entityStatement) throws Exception {
    log.info("Entity Statement issued by: {} - for: {}\n{}", entityStatement.getIssuer(), entityStatement.getSubject(),
      OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
        .writeValueAsString(entityStatement.getSignedJWT().getJWTClaimsSet().toJSONObject()));
  }



}