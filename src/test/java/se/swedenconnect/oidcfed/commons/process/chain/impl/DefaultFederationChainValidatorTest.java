package se.swedenconnect.oidcfed.commons.process.chain.impl;

import static org.junit.jupiter.api.Assertions.*;

import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import com.nimbusds.jose.jwk.JWKSet;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.oidcfed.commons.configuration.PolicyParameterFormats;
import se.swedenconnect.oidcfed.commons.data.metadata.OpMetadata;
import se.swedenconnect.oidcfed.commons.data.metadata.RelyingPartyMetadata;
import se.swedenconnect.oidcfed.commons.data.metadata.policy.EntityTypeMetadataPolicy;
import se.swedenconnect.oidcfed.commons.data.metadata.policy.MetadataParameterPolicy;
import se.swedenconnect.oidcfed.commons.data.oidcfed.ConstraintsClaim;
import se.swedenconnect.oidcfed.commons.data.oidcfed.EntityMetadataInfoClaim;
import se.swedenconnect.oidcfed.commons.data.oidcfed.EntityStatement;
import se.swedenconnect.oidcfed.commons.data.oidcfed.NamingConstraints;
import se.swedenconnect.oidcfed.commons.process.chain.ChainValidationException;
import se.swedenconnect.oidcfed.commons.process.chain.ChainValidationResult;
import se.swedenconnect.oidcfed.commons.process.chain.FederationChainValidator;
import se.swedenconnect.oidcfed.commons.process.metadata.MetadataPolicySerializer;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyOperatorFactory;
import se.swedenconnect.oidcfed.commons.process.metadata.impl.DefaultPolicyOperatorFactory;
import se.swedenconnect.oidcfed.commons.process.metadata.impl.StandardMetadataPolicySerializer;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.EssentialPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.SubsetOfPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.SupersetOfPolicyOperator;
import se.swedenconnect.oidcfed.commons.testdata.TestCredentials;
import se.swedenconnect.oidcfed.commons.testdata.TestEntityStatements;
import se.swedenconnect.oidcfed.commons.utils.OidcUtils;

/**
 * OpenID federation chain validation tests
 */
@Slf4j
class DefaultFederationChainValidatorTest {

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
  void testChainValidation() throws Exception {

    performChainTest("Chain with Entity Configuration", List.of(
        TestEntityStatements.ta1_conf(),
        TestEntityStatements.ta1_ie1_statement()
          .constraintsClaim(ConstraintsClaim.builder()
            .maxPathLength(2)
            .namingConstraints(NamingConstraints.builder()
              .excluded(List.of("http://excluded.example.com"))
              .permitted(List.of("https://example.com", "http://example.com"))
              .build())
            .allowedLeafEntityTypes(List.of("openid_relying_party", "openid_provider"))
            .build()),
        TestEntityStatements.ie1_ie2_statement(),
        TestEntityStatements.ie2_op1(),
        TestEntityStatements.op1_conf()),
      EntityMetadataInfoClaim.builder()
        .opMetadataObject(OpMetadata.builder()
          .scopesSupported(List.of("openid"))
          .claimsSupported(List.of("claim1", "claim2", "claim3"))
          .build().toJsonObject())
        .build(), null);

    performChainTest("Chain with no Entity Configuration", List.of(
        TestEntityStatements.ta1_conf(),
        TestEntityStatements.ta1_ie1_statement(),
        TestEntityStatements.ie1_ie2_statement(),
        TestEntityStatements.ie2_rp1_metadata()),
      EntityMetadataInfoClaim.builder()
        .oidcRelyingPartyMetadataObject(RelyingPartyMetadata.builder()
          .responseTypes(List.of("code"))
          .build().toJsonObject())
        .build(), null);

    performChainTest("Chain with Metadata restriction", List.of(
        TestEntityStatements.ta1_conf(),
        TestEntityStatements.ta1_ie1_statement(),
        TestEntityStatements.ie1_ie2_statement()
          .policy(EntityMetadataInfoClaim.builder()
            .opMetadataObject(serializer.toJsonObject(EntityTypeMetadataPolicy.builder()
              .addMetadataParameterPolicy(
                MetadataParameterPolicy.builder(PolicyParameterFormats.claims_supported.toMetadataParameter())
                  .add(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("claim1", "claim2"))
                  .build())
              .addMetadataParameterPolicy(
                MetadataParameterPolicy.builder(PolicyParameterFormats.scopes_supported.toMetadataParameter())
                  .add(SupersetOfPolicyOperator.OPERATOR_NAME, List.of("Bad1", "Bad2"))
                  .build())
              .build()))
            .oidcRelyingPartyMetadataObject(serializer.toJsonObject(EntityTypeMetadataPolicy.builder()
              .addMetadataParameterPolicy(
                MetadataParameterPolicy.builder(PolicyParameterFormats.response_types.toMetadataParameter())
                  .add(EssentialPolicyOperator.OPERATOR_NAME, true)
                  .build())
              .build()))
            .build()),
        TestEntityStatements.ie2_op1(),
        TestEntityStatements.op1_conf()),
      EntityMetadataInfoClaim.builder()
        .opMetadataObject(OpMetadata.builder()
          .scopesSupported(List.of("openid"))
          .claimsSupported(List.of("claim1", "claim2"))
          .build().toJsonObject())
        .build(), null);

    performChainTest("Chain with Metadata Merge conflict", List.of(
        TestEntityStatements.ta1_conf(),
        TestEntityStatements.ta1_ie1_statement(),
        TestEntityStatements.ie1_ie2_statement()
          .policy(EntityMetadataInfoClaim.builder()
            .opMetadataObject(serializer.toJsonObject(EntityTypeMetadataPolicy.builder()
              .addMetadataParameterPolicy(
                MetadataParameterPolicy.builder(PolicyParameterFormats.claims_supported.toMetadataParameter())
                  .add(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("claim1"))
                  .build())
              .build()))
            .oidcRelyingPartyMetadataObject(serializer.toJsonObject(EntityTypeMetadataPolicy.builder()
              .addMetadataParameterPolicy(
                MetadataParameterPolicy.builder(PolicyParameterFormats.response_types.toMetadataParameter())
                  .add(EssentialPolicyOperator.OPERATOR_NAME, true)
                  .build())
              .build()))
            .build()),
        TestEntityStatements.ie2_op1(),
        TestEntityStatements.op1_conf()),
      null, ChainValidationException.class);


    performChainTest("Chain with path len constraints error", List.of(
        TestEntityStatements.ta1_conf(),
        TestEntityStatements.ta1_ie1_statement()
          .constraintsClaim(ConstraintsClaim.builder()
            .maxPathLength(1)
            .build()),
        TestEntityStatements.ie1_ie2_statement(),
        TestEntityStatements.ie2_op1(),
        TestEntityStatements.op1_conf()), null, ChainValidationException.class);

    performChainTest("Chain with excluded name constraints error", List.of(
        TestEntityStatements.ta1_conf(),
        TestEntityStatements.ta1_ie1_statement()
          .constraintsClaim(ConstraintsClaim.builder()
            .namingConstraints(NamingConstraints.builder()
              .excluded(List.of("https://example.com"))
              .build())
            .build()),
        TestEntityStatements.ie1_ie2_statement(),
        TestEntityStatements.ie2_op1(),
        TestEntityStatements.op1_conf()), null, ChainValidationException.class);

    performChainTest("Chain with permitted name constraints error", List.of(
        TestEntityStatements.ta1_conf(),
        TestEntityStatements.ta1_ie1_statement()
          .constraintsClaim(ConstraintsClaim.builder()
            .namingConstraints(NamingConstraints.builder()
              .permitted(List.of("https://myexample.com"))
              .build())
            .build()),
        TestEntityStatements.ie1_ie2_statement(),
        TestEntityStatements.ie2_op1(),
        TestEntityStatements.op1_conf()), null, ChainValidationException.class);

    performChainTest("Chain with entity type constraints error", List.of(
        TestEntityStatements.ta1_conf(),
        TestEntityStatements.ta1_ie1_statement(),
        TestEntityStatements.ie1_ie2_statement()
          .constraintsClaim(ConstraintsClaim.builder()
            .allowedLeafEntityTypes(List.of("openid_relying_party"))
            .build()),
        TestEntityStatements.ie2_op1(),
        TestEntityStatements.op1_conf()), null, ChainValidationException.class);

    performChainTest("Mimimum chain", List.of(
      TestEntityStatements.ta1_conf()
        .constraintsClaim(ConstraintsClaim.builder()
          .maxPathLength(1)
          .build()),
      TestEntityStatements.ta1_op1_direct()
    ), EntityMetadataInfoClaim.builder()
      .opMetadataObject(OpMetadata.builder()
        .scopesSupported(List.of("openid"))
        .claimsSupported(List.of("claim1", "claim2", "claim3"))
        .build().toJsonObject())
      .build(), null);

  }

  void performChainTest(String message, List<TestEntityStatements.EsData.EsDataBuilder> builderChain,
    EntityMetadataInfoClaim expected, Class<? extends Exception> exceptionClass) throws Exception {
    log.info("Entity Statement chain validation test: " + message);
    if (exceptionClass != null) {
      Exception exception = assertThrows(exceptionClass, () -> {
        federationChainValidator.validate(builderChain.stream()
          .map(esDataBuilder -> TestEntityStatements.getEntityStatement(esDataBuilder.build()))
          .toList());
      });
      log.info("Caught expected exception {} with message: {}", exception.getClass().getSimpleName(),
        exception.getMessage());
      exception.printStackTrace();
      return;
    }

    List<EntityStatement> chain = builderChain.stream()
      .map(esDataBuilder -> TestEntityStatements.getEntityStatement(esDataBuilder.build()))
      .toList();
    log.info("Validated chain");
    for (EntityStatement entityStatement : chain) {
      logEntityStatementInfo(entityStatement);
    }

    ChainValidationResult validationResult = federationChainValidator.validate(chain);
    log.info("Target entity declared metadata:\n{}",
      OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
        .writeValueAsString(validationResult.getDeclaredMetadata()));
    String processedMetadata = OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
      .writeValueAsString(validationResult.getPolicyProcessedMetadata());
    log.info("Target entity policy processed metadata:\n{}",
      processedMetadata);

    String expectedJson = OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(expected);
    JSONAssert.assertEquals(expectedJson, processedMetadata, false);
  }

  private void logEntityStatementInfo(EntityStatement entityStatement) throws Exception {
    log.info("Entity Statement issued by: {} - for: {}\n{}", entityStatement.getIssuer(), entityStatement.getSubject(),
      OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
        .writeValueAsString(entityStatement.getSignedJWT().getJWTClaimsSet().toJSONObject()));
  }

}