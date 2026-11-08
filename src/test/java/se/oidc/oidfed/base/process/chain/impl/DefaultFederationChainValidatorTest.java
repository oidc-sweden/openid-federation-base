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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
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
                    .allowedEntityTypes(List.of("openid_relying_party", "openid_provider"))
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

  /**
   * The {@code allowed_entity_types} constraint is a removal of metadata and not a check, as specified in Section
   * 6.2.3 of OpenID Federation 1.0. A chain whose subject has an Entity Type that the constraint does not allow is
   * still valid, and the metadata of that Entity Type is removed from the resolved metadata.
   */
  @Test
  void testEntityTypeConstraints() throws Exception {

    // The subject is an OpenID Provider and the constraint allows openid_relying_party only, so all of its metadata
    // is removed. The chain remains valid and the metadata policy processing must cope with the empty result.
    final ChainValidationResult strippedResult = this.validateChain(List.of(
        TestEntityStatements.ta1_conf(),
        TestEntityStatements.ta1_ie1_statement(),
        TestEntityStatements.ie1_ie2_statement()
            .constraintsClaim(ConstraintsClaim.builder()
                .allowedEntityTypes(List.of("openid_relying_party"))
                .build()),
        TestEntityStatements.ie2_op1(),
        TestEntityStatements.op1_conf()));
    assertNull(strippedResult.getDeclaredMetadata().getOpMetadataObject());
    assertNull(strippedResult.getPolicyProcessedMetadata().getOpMetadataObject());

    // The same chain with a constraint that allows the Entity Type keeps the metadata
    final ChainValidationResult retainedResult = this.validateChain(List.of(
        TestEntityStatements.ta1_conf(),
        TestEntityStatements.ta1_ie1_statement(),
        TestEntityStatements.ie1_ie2_statement()
            .constraintsClaim(ConstraintsClaim.builder()
                .allowedEntityTypes(List.of("openid_relying_party", "openid_provider"))
                .build()),
        TestEntityStatements.ie2_op1(),
        TestEntityStatements.op1_conf()));
    assertNotNull(retainedResult.getDeclaredMetadata().getOpMetadataObject());
    assertNotNull(retainedResult.getPolicyProcessedMetadata().getOpMetadataObject());

    // An empty array allows federation_entity only, so the OpenID Provider metadata is removed
    final ChainValidationResult emptyConstraintResult = this.validateChain(List.of(
        TestEntityStatements.ta1_conf(),
        TestEntityStatements.ta1_ie1_statement(),
        TestEntityStatements.ie1_ie2_statement()
            .constraintsClaim(ConstraintsClaim.builder()
                .allowedEntityTypes(List.of())
                .build()),
        TestEntityStatements.ie2_op1(),
        TestEntityStatements.op1_conf()));
    assertNull(emptyConstraintResult.getDeclaredMetadata().getOpMetadataObject());

    // Constraints of separate statements are applied independently, which for a removal amounts to an intersection.
    // The superior allows both Entity Types and the subordinate allows only openid_relying_party, so the OpenID
    // Provider metadata is removed and a subordinate cannot widen what a superior allowed.
    final ChainValidationResult intersectedResult = this.validateChain(List.of(
        TestEntityStatements.ta1_conf(),
        TestEntityStatements.ta1_ie1_statement()
            .constraintsClaim(ConstraintsClaim.builder()
                .allowedEntityTypes(List.of("openid_relying_party", "openid_provider"))
                .build()),
        TestEntityStatements.ie1_ie2_statement()
            .constraintsClaim(ConstraintsClaim.builder()
                .allowedEntityTypes(List.of("openid_relying_party"))
                .build()),
        TestEntityStatements.ie2_op1(),
        TestEntityStatements.op1_conf()));
    assertNull(intersectedResult.getDeclaredMetadata().getOpMetadataObject());

    // A constraint declared by the Trust Anchor in its own Entity Configuration is honoured, consistent with how
    // this implementation treats the other constraints.
    final ChainValidationResult trustAnchorConstraintResult = this.validateChain(List.of(
        TestEntityStatements.ta1_conf()
            .constraintsClaim(ConstraintsClaim.builder()
                .allowedEntityTypes(List.of("openid_relying_party"))
                .build()),
        TestEntityStatements.ta1_ie1_statement(),
        TestEntityStatements.ie1_ie2_statement(),
        TestEntityStatements.ie2_op1(),
        TestEntityStatements.op1_conf()));
    assertNull(trustAnchorConstraintResult.getDeclaredMetadata().getOpMetadataObject());

    // Constraints are defined for Subordinate Statements only, so a constraint that the subject declares in its own
    // Entity Configuration has no effect and cannot be used to strip its own metadata.
    final ChainValidationResult selfConstraintResult = this.validateChain(List.of(
        TestEntityStatements.ta1_conf(),
        TestEntityStatements.ta1_ie1_statement(),
        TestEntityStatements.ie1_ie2_statement(),
        TestEntityStatements.ie2_op1(),
        TestEntityStatements.op1_conf()
            .constraintsClaim(ConstraintsClaim.builder()
                .allowedEntityTypes(List.of("openid_relying_party"))
                .build())));
    assertNotNull(selfConstraintResult.getDeclaredMetadata().getOpMetadataObject());

    // A chain that declares no allowed_entity_types constraint anywhere allows every Entity Type
    final ChainValidationResult unconstrainedResult = this.validateChain(List.of(
        TestEntityStatements.ta1_conf(),
        TestEntityStatements.ta1_ie1_statement(),
        TestEntityStatements.ie1_ie2_statement(),
        TestEntityStatements.ie2_op1(),
        TestEntityStatements.op1_conf()));
    assertNotNull(unconstrainedResult.getDeclaredMetadata().getOpMetadataObject());
  }

  /**
   * The {@code federation_entity} Entity Type is always allowed, MUST NOT be listed in the constraint and is never
   * removed, as specified in Section 6.2.3 of OpenID Federation 1.0.
   */
  @Test
  void testFederationEntityTypeIsNeverRemoved() throws Exception {

    final EntityMetadataInfoClaim subjectMetadata = EntityMetadataInfoClaim.builder()
        .opMetadataObject(TestMetadata.opMetadata_claims123)
        .federationEntityMetadataObject(TestMetadata.federationEntityMetadata)
        .build();

    // A constraint that does not list federation_entity still keeps it, while the Entity Type that is not allowed
    // is removed
    final ChainValidationResult result = this.validateChain(List.of(
        TestEntityStatements.ta1_conf(),
        TestEntityStatements.ta1_ie1_statement(),
        TestEntityStatements.ie1_ie2_statement()
            .constraintsClaim(ConstraintsClaim.builder()
                .allowedEntityTypes(List.of("openid_relying_party"))
                .build()),
        TestEntityStatements.ie2_op1(),
        TestEntityStatements.op1_conf().metadata(subjectMetadata)));
    assertNull(result.getDeclaredMetadata().getOpMetadataObject());
    assertNotNull(result.getDeclaredMetadata().getFederationEntityMetadataObject());
    assertNotNull(result.getPolicyProcessedMetadata().getFederationEntityMetadataObject());

    // An empty array allows federation_entity only, which is exactly what must remain
    final ChainValidationResult emptyConstraintResult = this.validateChain(List.of(
        TestEntityStatements.ta1_conf(),
        TestEntityStatements.ta1_ie1_statement(),
        TestEntityStatements.ie1_ie2_statement()
            .constraintsClaim(ConstraintsClaim.builder()
                .allowedEntityTypes(List.of())
                .build()),
        TestEntityStatements.ie2_op1(),
        TestEntityStatements.op1_conf().metadata(subjectMetadata)));
    assertNull(emptyConstraintResult.getDeclaredMetadata().getOpMetadataObject());
    assertNotNull(emptyConstraintResult.getDeclaredMetadata().getFederationEntityMetadataObject());
  }

  /**
   * The metadata policy of an Entity Type that the constraints removed is never applied, since Section 6.2.3
   * requires the removal to happen before metadata policies are applied.
   */
  @Test
  void testPolicyOfRemovedEntityTypeIsNotApplied() throws Exception {

    // This openid_provider policy demands a superset of scopes that the subject does not have, which fails chain
    // validation while the Entity Type survives - the "Chain with invalid policy merge" case of testChainValidation.
    final EntityMetadataInfoClaim failingOpPolicy = EntityMetadataInfoClaim.builder()
        .opMetadataObject(serializer.toJsonObject(EntityTypeMetadataPolicy.builder()
            .addMetadataParameterPolicy(
                MetadataParameterPolicy.builder(PolicyParameterFormats.scopes_supported.toMetadataParameter())
                    .add(SupersetOfPolicyOperator.OPERATOR_NAME, List.of("Bad1", "Bad2"))
                    .build())
            .build()))
        .build();

    // With the Entity Type removed by the constraint, the policy is never reached and the chain is valid
    final ChainValidationResult result = this.validateChain(List.of(
        TestEntityStatements.ta1_conf(),
        TestEntityStatements.ta1_ie1_statement(),
        TestEntityStatements.ie1_ie2_statement()
            .policy(failingOpPolicy)
            .constraintsClaim(ConstraintsClaim.builder()
                .allowedEntityTypes(List.of("openid_relying_party"))
                .build()),
        TestEntityStatements.ie2_op1(),
        TestEntityStatements.op1_conf()));
    assertNull(result.getDeclaredMetadata().getOpMetadataObject());
    assertNull(result.getPolicyProcessedMetadata().getOpMetadataObject());

    // Without the constraint the same chain fails on the policy, which is what makes the case above meaningful
    assertThrows(ChainValidationException.class, () -> this.validateChain(List.of(
        TestEntityStatements.ta1_conf(),
        TestEntityStatements.ta1_ie1_statement(),
        TestEntityStatements.ie1_ie2_statement()
            .policy(failingOpPolicy),
        TestEntityStatements.ie2_op1(),
        TestEntityStatements.op1_conf())));
  }

  private ChainValidationResult validateChain(final List<TestEntityStatements.EsData.EsDataBuilder> builderChain)
      throws Exception {
    return federationChainValidator.validate(builderChain.stream()
        .map(esDataBuilder -> TestEntityStatements.getEntityStatement(esDataBuilder.build()))
        .toList());
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
        OidcUtils.JSON_MAPPER.writerWithDefaultPrettyPrinter()
            .writeValueAsString(validationResult.getDeclaredMetadata()));
    final String processedMetadata = OidcUtils.JSON_MAPPER.writerWithDefaultPrettyPrinter()
        .writeValueAsString(validationResult.getPolicyProcessedMetadata());
    log.info("Target entity policy processed metadata:\n{}",
        processedMetadata);

    final String expectedJson = OidcUtils.JSON_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(expected);
    JSONAssert.assertEquals(expectedJson, processedMetadata, false);
  }

  private void logEntityStatementInfo(final EntityStatement entityStatement) throws Exception {
    log.info("Entity Statement issued by: {} - for: {}\n{}", entityStatement.getIssuer(), entityStatement.getSubject(),
        OidcUtils.JSON_MAPPER.writerWithDefaultPrettyPrinter()
            .writeValueAsString(entityStatement.getSignedJWT().getJWTClaimsSet().toJSONObject()));
  }

}
