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
package se.oidc.oidfed.base.process.chain.impl;

import com.nimbusds.jose.jwk.JWKSet;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import se.oidc.oidfed.base.configuration.PolicyParameterFormats;
import se.oidc.oidfed.base.data.metadata.policy.EntityTypeMetadataPolicy;
import se.oidc.oidfed.base.data.metadata.policy.MetadataParameterPolicy;
import se.oidc.oidfed.base.data.federation.ConstraintsClaim;
import se.oidc.oidfed.base.data.federation.EntityMetadataInfoClaim;
import se.oidc.oidfed.base.data.federation.EntityStatement;
import se.oidc.oidfed.base.data.federation.NamingConstraints;
import se.oidc.oidfed.base.process.chain.ChainValidationException;
import se.oidc.oidfed.base.process.chain.ChainValidationResult;
import se.oidc.oidfed.base.process.chain.FederationChainValidator;
import se.oidc.oidfed.base.process.metadata.MetadataPolicySerializer;
import se.oidc.oidfed.base.process.metadata.PolicyOperatorFactory;
import se.oidc.oidfed.base.process.metadata.impl.DefaultPolicyOperatorFactory;
import se.oidc.oidfed.base.process.metadata.impl.StandardMetadataPolicySerializer;
import se.oidc.oidfed.base.process.metadata.policyoperators.EssentialPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.SubsetOfPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.SupersetOfPolicyOperator;
import se.oidc.oidfed.base.testdata.TestCredentials;
import se.oidc.oidfed.base.testdata.TestEntityStatements;
import se.oidc.oidfed.base.testdata.TestMetadata;
import se.oidc.oidfed.base.utils.OidcUtils;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * OpenID federation chain validation tests.
 */
@Slf4j
class DefaultFederationChainValidatorTest {

  static PolicyOperatorFactory policyOperatorFactory;
  static MetadataPolicySerializer serializer;

  static FederationChainValidator federationChainValidator;

  @BeforeAll
  static void init() {

    final JWKSet t1JwkSet = TestCredentials.getJwkSet(TestCredentials.ta1.getCertificate());

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

    this.performChainTest("Chain with Entity Configuration", List.of(
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
            .opMetadataObject(TestMetadata.opMetadata_claims123)
            .build(), null);

    this.performChainTest("Chain with no Entity Configuration", List.of(
            TestEntityStatements.ta1_conf(),
            TestEntityStatements.ta1_ie1_statement(),
            TestEntityStatements.ie1_ie2_statement(),
            TestEntityStatements.ie2_rp1_metadata()),
        EntityMetadataInfoClaim.builder()
            .oidcRelyingPartyMetadataObject(TestMetadata.rpMetadata_rt)
            .build(), ChainValidationException.class);

    this.performChainTest("Chain with invalid policy merge", List.of(
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
            .opMetadataObject(TestMetadata.opMetadata_claims12)
            .build(), ChainValidationException.class);

    this.performChainTest("Chain with Metadata Merge conflict", List.of(
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

    this.performChainTest("Chain with path len constraints error", List.of(
        TestEntityStatements.ta1_conf(),
        TestEntityStatements.ta1_ie1_statement()
            .constraintsClaim(ConstraintsClaim.builder()
                .maxPathLength(1)
                .build()),
        TestEntityStatements.ie1_ie2_statement(),
        TestEntityStatements.ie2_op1(),
        TestEntityStatements.op1_conf()), null, ChainValidationException.class);

    this.performChainTest("Chain with excluded name constraints error", List.of(
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

    this.performChainTest("Chain with permitted name constraints error", List.of(
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

    this.performChainTest("Chain with entity type constraints error", List.of(
        TestEntityStatements.ta1_conf(),
        TestEntityStatements.ta1_ie1_statement(),
        TestEntityStatements.ie1_ie2_statement()
            .constraintsClaim(ConstraintsClaim.builder()
                .allowedLeafEntityTypes(List.of("openid_relying_party"))
                .build()),
        TestEntityStatements.ie2_op1(),
        TestEntityStatements.op1_conf()), null, ChainValidationException.class);

    this.performChainTest("Mimimum chain", List.of(
        TestEntityStatements.ta1_conf()
            .constraintsClaim(ConstraintsClaim.builder()
                .maxPathLength(1)
                .build()),
        TestEntityStatements.ta1_op1_direct()
    ), EntityMetadataInfoClaim.builder()
        .opMetadataObject(TestMetadata.opMetadata_claims123)
        .build(), ChainValidationException.class);

  }

  void performChainTest(final String message, final List<TestEntityStatements.EsData.EsDataBuilder> builderChain,
      final EntityMetadataInfoClaim expected, final Class<? extends Exception> exceptionClass) throws Exception {
    log.info("Entity Statement chain validation test: {}", message);
    final List<EntityStatement> chain = builderChain.stream()
        .map(esDataBuilder -> TestEntityStatements.getEntityStatement(esDataBuilder.build()))
        .toList();
    log.info("Validated chain");
    for (final EntityStatement entityStatement : chain) {
      this.logEntityStatementInfo(entityStatement);
    }

    if (exceptionClass != null) {
      final Exception exception =
          assertThrows(exceptionClass, () -> federationChainValidator.validate(builderChain.stream()
              .map(esDataBuilder -> TestEntityStatements.getEntityStatement(esDataBuilder.build()))
              .toList()));
      log.info("Caught expected exception {} with message: {}", exception.getClass().getSimpleName(),
          exception.getMessage());
      return;
    }

    final ChainValidationResult validationResult = federationChainValidator.validate(chain);
    log.info("Target entity declared metadata:\n{}",
        OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
            .writeValueAsString(validationResult.getDeclaredMetadata()));
    final String processedMetadata = OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
        .writeValueAsString(validationResult.getPolicyProcessedMetadata());
    log.info("Target entity policy processed metadata:\n{}",
        processedMetadata);

    final String expectedJson = OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(expected);
    JSONAssert.assertEquals(expectedJson, processedMetadata, false);
  }

  private void logEntityStatementInfo(final EntityStatement entityStatement) throws Exception {
    log.info("Entity Statement issued by: {} - for: {}\n{}", entityStatement.getIssuer(), entityStatement.getSubject(),
        OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
            .writeValueAsString(entityStatement.getSignedJWT().getJWTClaimsSet().toJSONObject()));
  }

}
