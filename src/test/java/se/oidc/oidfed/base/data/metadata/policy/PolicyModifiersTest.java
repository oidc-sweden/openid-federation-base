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
package se.oidc.oidfed.base.data.metadata.policy;

import com.nimbusds.jose.JWSHeader;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.oidc.oidfed.base.configuration.MetadataParameter;
import se.oidc.oidfed.base.configuration.PolicyParameterFormats;
import se.oidc.oidfed.base.data.federation.EntityMetadataInfoClaim;
import se.oidc.oidfed.base.data.federation.EntityStatement;
import se.oidc.oidfed.base.data.federation.EntityStatementDefinedParams;
import se.oidc.oidfed.base.process.metadata.MetadataPolicySerializer;
import se.oidc.oidfed.base.process.metadata.PolicyOperatorFactory;
import se.oidc.oidfed.base.process.metadata.PolicyProcessingException;
import se.oidc.oidfed.base.process.metadata.PolicyTranslationException;
import se.oidc.oidfed.base.process.metadata.impl.DefaultPolicyOperatorFactory;
import se.oidc.oidfed.base.process.metadata.impl.SkipSubordniatePolicyOperatorFactory;
import se.oidc.oidfed.base.process.metadata.impl.StandardMetadataPolicySerializer;
import se.oidc.oidfed.base.process.metadata.policyoperators.AddPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.DefaultPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.EssentialPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.IntersectsPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.OneOfPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.RegexpPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.SkipSubordinatesPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.SubsetOfPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.SupersetOfPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.ValuePolicyOperator;
import se.oidc.oidfed.base.testdata.PolicyData;
import se.oidc.oidfed.base.testdata.TestCredentials;
import se.oidc.oidfed.base.utils.OidcUtils;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * PolicyOperator tests
 */
@Slf4j
class PolicyModifiersTest {

  static PolicyOperatorFactory policyOperatorFactory;
  static MetadataPolicySerializer serializer;
  static PolicyOperatorFactory skipSubordinatesPolicyOperatorFactory;
  static MetadataPolicySerializer skipSubordinatesSerializer;

  @BeforeAll
  static void init() {
    policyOperatorFactory = DefaultPolicyOperatorFactory.getInstance();
    serializer = new StandardMetadataPolicySerializer(policyOperatorFactory,
        Arrays.stream(PolicyParameterFormats.values())
            .collect(
                Collectors.toMap(PolicyParameterFormats::getParameterName, PolicyParameterFormats::toMetadataParameter))
    );
    skipSubordinatesPolicyOperatorFactory = SkipSubordniatePolicyOperatorFactory.getInstance();
    skipSubordinatesSerializer = new StandardMetadataPolicySerializer(skipSubordinatesPolicyOperatorFactory,
        Arrays.stream(PolicyParameterFormats.values())
            .collect(
                Collectors.toMap(PolicyParameterFormats::getParameterName, PolicyParameterFormats::toMetadataParameter))
    );
  }

  @Test
  void policyModifiersTest() throws Exception {

    this.testPolicyOperators(
        "String value modifier with no value",
        PolicyParameterFormats.issuer.toMetadataParameter(),
        List.of(
            new PolicyData(ValuePolicyOperator.OPERATOR_NAME, null)
        ), PolicyProcessingException.class
    );
    this.testPolicyOperators(
        "String value modifier",
        PolicyParameterFormats.issuer.toMetadataParameter(),
        List.of(
            new PolicyData(ValuePolicyOperator.OPERATOR_NAME, "Value")
        ), null
    );
    this.testPolicyOperators(
        "String value with declared array values",
        PolicyParameterFormats.subject_types_supported.toMetadataParameter(),
        List.of(
            new PolicyData(DefaultPolicyOperator.OPERATOR_NAME, "Default Value")
        ), PolicyTranslationException.class
    );
    this.testPolicyOperators(
        "Declared array values",
        PolicyParameterFormats.subject_types_supported.toMetadataParameter(),
        List.of(
            new PolicyData(DefaultPolicyOperator.OPERATOR_NAME, List.of("Value1", "Value2"))
        ), null
    );
    this.testPolicyOperators(
        "Integer test",
        PolicyParameterFormats.default_max_age.toMetadataParameter(),
        List.of(
            new PolicyData(DefaultPolicyOperator.OPERATOR_NAME, 1234)
        ), null
    );
    this.testPolicyOperators(
        "Integer test with string input",
        PolicyParameterFormats.default_max_age.toMetadataParameter(),
        List.of(
            new PolicyData(DefaultPolicyOperator.OPERATOR_NAME, "1234")
        ), PolicyProcessingException.class
    );
    this.testPolicyOperators(
        "Illegal Integer test",
        PolicyParameterFormats.default_max_age.toMetadataParameter(),
        List.of(
            new PolicyData(DefaultPolicyOperator.OPERATOR_NAME, "M1234")
        ), PolicyTranslationException.class
    );
    this.testPolicyOperators(
        "Boolean test",
        PolicyParameterFormats.claims_parameter_supported.toMetadataParameter(),
        List.of(
            new PolicyData(DefaultPolicyOperator.OPERATOR_NAME, true)
        ), null
    );
    this.testPolicyOperators(
        "Boolean test string value",
        PolicyParameterFormats.claims_parameter_supported.toMetadataParameter(),
        List.of(
            new PolicyData(DefaultPolicyOperator.OPERATOR_NAME, "true")
        ), PolicyProcessingException.class
    );
    this.testPolicyOperators(
        "Illegal Boolean test",
        PolicyParameterFormats.claims_parameter_supported.toMetadataParameter(),
        List.of(
            new PolicyData(DefaultPolicyOperator.OPERATOR_NAME, "maybe")
        ), PolicyTranslationException.class
    );
    this.testPolicyOperators(
        "All values String test",
        PolicyParameterFormats.issuer.toMetadataParameter(),
        List.of(
            new PolicyData(ValuePolicyOperator.OPERATOR_NAME, "Value"),
            new PolicyData(AddPolicyOperator.OPERATOR_NAME, List.of("Value")),
            new PolicyData(DefaultPolicyOperator.OPERATOR_NAME, "Default"),
            new PolicyData(OneOfPolicyOperator.OPERATOR_NAME, List.of("Value", "Another value")),
            new PolicyData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("Value", "Another value")),
            new PolicyData(SupersetOfPolicyOperator.OPERATOR_NAME, List.of("Value")),
            new PolicyData(EssentialPolicyOperator.OPERATOR_NAME, true),
            new PolicyData(SkipSubordinatesPolicyOperator.OPERATOR_NAME, true),
            new PolicyData(RegexpPolicyOperator.OPERATOR_NAME, "^Value$"),
            new PolicyData(IntersectsPolicyOperator.OPERATOR_NAME, List.of("Value", "Another value"))
        ), null
    );
    this.testPolicyOperators(
        "All values String array test",
        PolicyParameterFormats.scopes_supported.toMetadataParameter(),
        List.of(
            new PolicyData(ValuePolicyOperator.OPERATOR_NAME, List.of("Value")),
            new PolicyData(AddPolicyOperator.OPERATOR_NAME, List.of("Another value")),
            new PolicyData(DefaultPolicyOperator.OPERATOR_NAME, List.of("Default")),
            new PolicyData(OneOfPolicyOperator.OPERATOR_NAME, List.of("Value", "Another value")),
            new PolicyData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("Value", "Another value")),
            new PolicyData(SupersetOfPolicyOperator.OPERATOR_NAME, List.of("Value")),
            new PolicyData(EssentialPolicyOperator.OPERATOR_NAME, true),
            new PolicyData(SkipSubordinatesPolicyOperator.OPERATOR_NAME, true),
            new PolicyData(RegexpPolicyOperator.OPERATOR_NAME, "^Value$"),
            new PolicyData(IntersectsPolicyOperator.OPERATOR_NAME, List.of("Value", "Another value"))
        ), null
    );

    this.testPolicyOperators(
        "Illegal mix - String array",
        PolicyParameterFormats.issuer.toMetadataParameter(),
        List.of(
            new PolicyData(ValuePolicyOperator.OPERATOR_NAME, List.of("Value", "Another value"))
        ), PolicyTranslationException.class
    );

    this.testPolicyOperators(
        "Space separated string",
        PolicyParameterFormats.issuer.toMetadataParameter(),
        List.of(
            new PolicyData(ValuePolicyOperator.OPERATOR_NAME, "scope1 scope2 scope3"),
            new PolicyData(AddPolicyOperator.OPERATOR_NAME, List.of("scope4")),
            new PolicyData(DefaultPolicyOperator.OPERATOR_NAME, "scope1 scope2"),
            new PolicyData(OneOfPolicyOperator.OPERATOR_NAME,
                List.of("scope1", "scope2", "scope3", "scope4")),
            new PolicyData(SubsetOfPolicyOperator.OPERATOR_NAME,
                List.of("scope1", "scope2", "scope3", "scope4")),
            new PolicyData(SupersetOfPolicyOperator.OPERATOR_NAME, List.of("scope1", "scope2"))
        ), null
    );
  }

  @Test
  void entityStatementParsingTest() throws Exception {

    final EntityStatement entityStatement = EntityStatement.builder()
        .issuer("issuer")
        .subject("subject")
        .issueTime(new Date())
        .expriationTime(Date.from(Instant.now().plusSeconds(600)))
        .definedParams(EntityStatementDefinedParams.builder()
            .metadataPolicy(EntityMetadataInfoClaim.builder()
                .opMetadataObject(skipSubordinatesSerializer.toJsonObject(EntityTypeMetadataPolicy.builder()
                    .addMetadataParameterPolicy(
                        MetadataParameterPolicy.builder(PolicyParameterFormats.issuer.toMetadataParameter())
                            .add(ValuePolicyOperator.OPERATOR_NAME, "Value")
                            .add(RegexpPolicyOperator.OPERATOR_NAME, "test")
                            .build())
                    .addMetadataParameterPolicy(MetadataParameterPolicy.builder(
                            PolicyParameterFormats.request_uri_parameter_supported.toMetadataParameter())
                        .add(DefaultPolicyOperator.OPERATOR_NAME, true).build())
                    .addMetadataParameterPolicy(
                        MetadataParameterPolicy.builder(PolicyParameterFormats.scopes_supported.toMetadataParameter(),
                                SkipSubordniatePolicyOperatorFactory.getInstance())
                            .add(SupersetOfPolicyOperator.OPERATOR_NAME, List.of("openid"))
                            .add(SkipSubordinatesPolicyOperator.OPERATOR_NAME, true)
                            .build())
                    .build()))
                .build())
            .build())
        .build(TestCredentials.p256JwtCredential, null);

    log.info("Entity Statement:\n{}", entityStatement.getSignedJWT().serialize());
    final JWSHeader entityStatementHeader = entityStatement.getSignedJWT().getHeader();
    log.info("Header: \n{}", OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(
        entityStatementHeader.toJSONObject()));
    assertEquals("entity-statement+jwt", entityStatementHeader.getType().getType());

    final Map<String, Object> entityStatementPayloadJsonObject = entityStatement.getSignedJWT()
        .getJWTClaimsSet()
        .toJSONObject();
    final String entityStatementPayloadJson = OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
        .writeValueAsString(entityStatementPayloadJsonObject);
    log.info("Entity statement payload:\n{}", entityStatementPayloadJson);

    final EntityMetadataInfoClaim metadataPolicyClaim = entityStatement.getMetadataPolicy();
    final EntityTypeMetadataPolicy entityTypeMetadataPolicy = skipSubordinatesSerializer.fromJsonObject(
        metadataPolicyClaim.getOpMetadataObject(), new ArrayList<>());

    final String entityPolicyJsonString = OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
        .writeValueAsString(skipSubordinatesSerializer.toJsonObject(entityTypeMetadataPolicy));
    log.info("OP Entity metadata policy:\n{}", entityPolicyJsonString);
  }

  private void testPolicyOperators(final String description, final MetadataParameter metadataParameter,
      final List<PolicyData> policyDataList, final Class<? extends Exception> exception)
      throws Exception {
    log.info(description);
    log.info("Metadata parameter: {}", metadataParameter);
    for (final PolicyData policyData : policyDataList) {
      log.info("policy: {} with value: {}", policyData.getPolicy(), policyData.getValue());
    }
    log.info("Expected exception: {}", exception);

    if (exception == null) {
      final MetadataParameterPolicy.MetadataParameterPolicyBuilder mdpBuilder = MetadataParameterPolicy.builder(
          metadataParameter, SkipSubordniatePolicyOperatorFactory.getInstance());
      for (final PolicyData policyData : policyDataList) {
        mdpBuilder.add(policyData.getPolicy(), policyData.getValue());
      }
      final MetadataParameterPolicy metadataParameterPolicy = mdpBuilder.build();
      final EntityTypeMetadataPolicy entityTypeMetadataPolicy = EntityTypeMetadataPolicy.builder()
          .addMetadataParameterPolicy(metadataParameterPolicy)
          .build();

      final String jsonString = OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
          .writeValueAsString(skipSubordinatesSerializer.toJsonObject(entityTypeMetadataPolicy));
      log.info("Policy modifiers JSON:\n{}", jsonString);
    }
    else {
      final Exception caughtException = assertThrows(exception, () -> {
        final MetadataParameterPolicy.MetadataParameterPolicyBuilder mdpBuilder = MetadataParameterPolicy.builder(
            metadataParameter);
        for (final PolicyData policyData : policyDataList) {
          mdpBuilder.add(policyData.getPolicy(), policyData.getValue());
        }
        mdpBuilder.build();
      });
      log.info("Caught expected {} with message: {}", caughtException.getClass().getSimpleName(),
          caughtException.getMessage());
    }
    log.info("Test success\n");
  }

}
