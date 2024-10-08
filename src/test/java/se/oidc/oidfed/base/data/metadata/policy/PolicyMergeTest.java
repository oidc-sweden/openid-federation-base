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

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.oidc.oidfed.base.configuration.MetadataParameter;
import se.oidc.oidfed.base.configuration.PolicyParameterFormats;
import se.oidc.oidfed.base.process.metadata.MetadataPolicySerializer;
import se.oidc.oidfed.base.process.metadata.PolicyOperatorFactory;
import se.oidc.oidfed.base.process.metadata.impl.DefaultPolicyOperatorFactory;
import se.oidc.oidfed.base.process.metadata.impl.SkipSubordniatePolicyOperatorFactory;
import se.oidc.oidfed.base.process.metadata.impl.StandardMetadataPolicySerializer;
import se.oidc.oidfed.base.process.metadata.policyoperators.OneOfPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.PolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.SkipSubordinatesPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.SubsetOfPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.SupersetOfPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.ValuePolicyOperator;
import se.oidc.oidfed.base.utils.OidcUtils;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Testing policy merge
 */
@Slf4j
public class PolicyMergeTest {

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
  void mergeTest() throws Exception {

    this.testPolicyMerge("Basic merge",
        EtPolicyData.builder()
            .metadataParameters(List.of(
                MdParamData.builder()
                    .metadataParameter(PolicyParameterFormats.scopes_supported.toMetadataParameter())
                    .operators(List.of(
                        new MdOperatorData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("value1", "value2"))
                    )).build()
            )).build(),
        EtPolicyData.builder()
            .metadataParameters(List.of(
                MdParamData.builder()
                    .metadataParameter(PolicyParameterFormats.scopes_supported.toMetadataParameter())
                    .operators(List.of(
                        new MdOperatorData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("value2", "value3"))
                    )).build()
            )).build(),
        EtPolicyData.builder()
            .metadataParameters(List.of(
                MdParamData.builder()
                    .metadataParameter(PolicyParameterFormats.scopes_supported.toMetadataParameter())
                    .operators(List.of(
                        new MdOperatorData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("value2"))
                    )).build()
            )).build()
    );

    this.testPolicyMerge("Different operators merge",
        EtPolicyData.builder()
            .metadataParameters(
                List.of(MdParamData.builder()
                    .metadataParameter(PolicyParameterFormats.scopes_supported.toMetadataParameter())
                    .operators(List.of(
                        new MdOperatorData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("value1", "value2"))
                    )).build()
                )).build(),
        EtPolicyData.builder()
            .metadataParameters(
                List.of(MdParamData.builder()
                    .metadataParameter(PolicyParameterFormats.scopes_supported.toMetadataParameter())
                    .operators(List.of(
                        new MdOperatorData(SupersetOfPolicyOperator.OPERATOR_NAME, List.of("value2", "value3"))
                    )).build()
                )).build(),
        EtPolicyData.builder()
            .metadataParameters(
                List.of(MdParamData.builder()
                    .metadataParameter(PolicyParameterFormats.scopes_supported.toMetadataParameter())
                    .operators(List.of(
                        new MdOperatorData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("value1", "value2")),
                        new MdOperatorData(SupersetOfPolicyOperator.OPERATOR_NAME, List.of("value2", "value3"))
                    )).build()
                )).build()
    );

    this.testPolicyMerge("Merge with skip operator",
        EtPolicyData.builder()
            .metadataParameters(
                List.of(MdParamData.builder()
                    .metadataParameter(PolicyParameterFormats.scopes_supported.toMetadataParameter())
                    .operators(List.of(
                        new MdOperatorData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("value1", "value2")),
                        new MdOperatorData(SkipSubordinatesPolicyOperator.OPERATOR_NAME, true)
                    )).build()
                )).build(),
        EtPolicyData.builder()
            .metadataParameters(
                List.of(MdParamData.builder()
                    .metadataParameter(PolicyParameterFormats.scopes_supported.toMetadataParameter())
                    .operators(List.of(
                        new MdOperatorData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("Value4")),
                        new MdOperatorData(SupersetOfPolicyOperator.OPERATOR_NAME, List.of("value2", "value3"))
                    )).build()
                )).build(),
        EtPolicyData.builder()
            .metadataParameters(
                List.of(MdParamData.builder()
                    .metadataParameter(PolicyParameterFormats.scopes_supported.toMetadataParameter())
                    .operators(List.of(
                        new MdOperatorData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("value1", "value2")),
                        new MdOperatorData(SkipSubordinatesPolicyOperator.OPERATOR_NAME, true)
                    )).build()
                )).build()
    );

    this.testPolicyMerge("Merge with different parameter policy",
        EtPolicyData.builder()
            .metadataParameters(
                List.of(
                    MdParamData.builder()
                        .metadataParameter(PolicyParameterFormats.scopes_supported.toMetadataParameter())
                        .operators(List.of(
                            new MdOperatorData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("value1", "value2"))
                        )).build()
                )).build(),
        EtPolicyData.builder()
            .metadataParameters(
                List.of(
                    MdParamData.builder()
                        .metadataParameter(PolicyParameterFormats.issuer.toMetadataParameter())
                        .operators(List.of(
                            new MdOperatorData(ValuePolicyOperator.OPERATOR_NAME, "Issuer name"),
                            new MdOperatorData(OneOfPolicyOperator.OPERATOR_NAME,
                                List.of("Issuer name", "Issuer alt name"))
                        )).build()
                )).build(),
        EtPolicyData.builder()
            .metadataParameters(
                List.of(
                    MdParamData.builder()
                        .metadataParameter(PolicyParameterFormats.scopes_supported.toMetadataParameter())
                        .operators(List.of(
                            new MdOperatorData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("value1", "value2"))
                        )).build(),
                    MdParamData.builder()
                        .metadataParameter(PolicyParameterFormats.issuer.toMetadataParameter())
                        .operators(List.of(
                            new MdOperatorData(ValuePolicyOperator.OPERATOR_NAME, "Issuer name"),
                            new MdOperatorData(OneOfPolicyOperator.OPERATOR_NAME,
                                List.of("Issuer name", "Issuer alt name"))
                        )).build()
                )).build()
    );

    this.testPolicyMerge("Merge with different parameter policy with skip",
        EtPolicyData.builder()
            .metadataParameters(
                List.of(
                    MdParamData.builder()
                        .metadataParameter(PolicyParameterFormats.scopes_supported.toMetadataParameter())
                        .operators(List.of(
                            new MdOperatorData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("value1", "value2")),
                            new MdOperatorData(SkipSubordinatesPolicyOperator.OPERATOR_NAME, true)
                        )).build()
                )).build(),
        EtPolicyData.builder()
            .metadataParameters(
                List.of(
                    MdParamData.builder()
                        .metadataParameter(PolicyParameterFormats.scopes_supported.toMetadataParameter())
                        .operators(List.of(
                            new MdOperatorData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("value4", "value5"))
                        )).build(),
                    MdParamData.builder()
                        .metadataParameter(PolicyParameterFormats.issuer.toMetadataParameter())
                        .operators(List.of(
                            new MdOperatorData(ValuePolicyOperator.OPERATOR_NAME, "Issuer name"),
                            new MdOperatorData(OneOfPolicyOperator.OPERATOR_NAME,
                                List.of("Issuer name", "Issuer alt name"))
                        )).build()
                )).build(),
        EtPolicyData.builder()
            .metadataParameters(
                List.of(
                    MdParamData.builder()
                        .metadataParameter(PolicyParameterFormats.scopes_supported.toMetadataParameter())
                        .operators(List.of(
                            new MdOperatorData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("value1", "value2")),
                            new MdOperatorData(SkipSubordinatesPolicyOperator.OPERATOR_NAME, true)
                        )).build(),
                    MdParamData.builder()
                        .metadataParameter(PolicyParameterFormats.issuer.toMetadataParameter())
                        .operators(List.of(
                            new MdOperatorData(ValuePolicyOperator.OPERATOR_NAME, "Issuer name"),
                            new MdOperatorData(OneOfPolicyOperator.OPERATOR_NAME,
                                List.of("Issuer name", "Issuer alt name"))
                        )).build()
                )).build()
    );

    this.testPolicyMerge("Merge with Null policy",
        EtPolicyData.builder()
            .metadataParameters(
                List.of(
                    MdParamData.builder()
                        .metadataParameter(PolicyParameterFormats.scopes_supported.toMetadataParameter())
                        .operators(List.of(
                            new MdOperatorData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("value4", "value5"))
                        )).build(),
                    MdParamData.builder()
                        .metadataParameter(PolicyParameterFormats.issuer.toMetadataParameter())
                        .operators(List.of(
                            new MdOperatorData(ValuePolicyOperator.OPERATOR_NAME, "Issuer name"),
                            new MdOperatorData(OneOfPolicyOperator.OPERATOR_NAME,
                                List.of("Issuer name", "Issuer alt name"))
                        )).build()
                )).build(),
        null,
        EtPolicyData.builder()
            .metadataParameters(
                List.of(
                    MdParamData.builder()
                        .metadataParameter(PolicyParameterFormats.scopes_supported.toMetadataParameter())
                        .operators(List.of(
                            new MdOperatorData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("value4", "value5"))
                        )).build(),
                    MdParamData.builder()
                        .metadataParameter(PolicyParameterFormats.issuer.toMetadataParameter())
                        .operators(List.of(
                            new MdOperatorData(ValuePolicyOperator.OPERATOR_NAME, "Issuer name"),
                            new MdOperatorData(OneOfPolicyOperator.OPERATOR_NAME,
                                List.of("Issuer name", "Issuer alt name"))
                        )).build()
                )).build()
    );

  }

  private void testPolicyMerge(final String message, final EtPolicyData superior, final EtPolicyData subordinate,
      final EtPolicyData expected)
      throws Exception {
    log.info(message);
    final EntityTypeMetadataPolicy superiorPolicy = this.getEtMetadataPolicy(superior);
    log.info("Superior policy: \n{}", OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(
        skipSubordinatesSerializer.toJsonObject(superiorPolicy)
    ));
    final EntityTypeMetadataPolicy subordinatePolicy = this.getEtMetadataPolicy(subordinate);
    log.info("Subordinate policy: \n{}", subordinatePolicy == null
        ? null
        : OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(
            skipSubordinatesSerializer.toJsonObject(subordinatePolicy))
    );

    final EntityTypeMetadataPolicy mergedPolicy = superiorPolicy.mergeWithSubordinate(subordinatePolicy);
    log.info("Merged policy: \n{}", OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(
        skipSubordinatesSerializer.toJsonObject(mergedPolicy)
    ));

    final EntityTypeMetadataPolicy expectedPolicy = this.getEtMetadataPolicy(expected);
    final Map<String, MetadataParameterPolicy> mergedPolicyMap = mergedPolicy.getMetadataParameterPolicyMap();
    final Map<String, MetadataParameterPolicy> expectedPolicyMap = expectedPolicy.getMetadataParameterPolicyMap();
    assertEquals(expectedPolicyMap.keySet().size(), mergedPolicyMap.keySet().size(), "Parameter count mismatch");
    assertTrue(expectedPolicyMap.keySet().stream().allMatch(mergedPolicyMap::containsKey), "Parameter names mismatch");
    for (final String parameterName : expectedPolicyMap.keySet()) {
      final MetadataParameterPolicy expectedParameterPolicy = expectedPolicyMap.get(parameterName);
      final MetadataParameterPolicy mergedParameterPolicy = mergedPolicyMap.get(parameterName);
      if (expectedParameterPolicy instanceof SkipSubMetadataParameterPolicy) {
        assertEquals(((SkipSubMetadataParameterPolicy) expectedParameterPolicy).isSkipSubordinates(),
            ((SkipSubMetadataParameterPolicy) mergedParameterPolicy).isSkipSubordinates(),
            "Skip subordinates mismatch");
      }
      final Map<String, PolicyOperator> expectedOperators = expectedParameterPolicy.getPolicyOperators();
      final Map<String, PolicyOperator> mergedOperators = mergedParameterPolicy.getPolicyOperators();
      assertEquals(expectedOperators.keySet().size(), mergedOperators.keySet().size(),
          "Policy operator count mismatch");
      assertTrue(expectedOperators.keySet().stream().allMatch(mergedOperators::containsKey),
          "Policy operator names mismatch");
      for (final String operatorName : expectedOperators.keySet()) {
        final PolicyOperator expectedOperator = expectedOperators.get(operatorName);
        final PolicyOperator mergedOperator = mergedOperators.get(operatorName);
        assertEquals(expectedOperator.getName(), mergedOperator.getName(), "Operator name mismatch");
        assertEquals(expectedOperator.getPolicyOperatorValue(), mergedOperator.getPolicyOperatorValue(),
            "Operator value mismatch");
      }
    }
    log.info("Merge test complete\n");
  }

  private EntityTypeMetadataPolicy getEtMetadataPolicy(final EtPolicyData etPolicyData) throws Exception {

    if (etPolicyData == null) {
      return null;
    }

    final EntityTypeMetadataPolicy.EntityTypeMetadataPolicyBuilder entityTypeMetadataPolicyBuilder =
        EntityTypeMetadataPolicy.builder();
    for (final MdParamData mdParamData : etPolicyData.getMetadataParameters()) {
      final SkipSubMetadataParameterPolicy.SkipSubMetadataParameterPolicyBuilder parameterPolicyBuilder =
          SkipSubMetadataParameterPolicy.builder(
              mdParamData.getMetadataParameter(), new SkipSubordniatePolicyOperatorFactory());
      for (final MdOperatorData operatorData : mdParamData.getOperators()) {
        parameterPolicyBuilder.add(operatorData.getName(), operatorData.getValue());
      }
      entityTypeMetadataPolicyBuilder.addMetadataParameterPolicy(parameterPolicyBuilder.build());
    }
    return entityTypeMetadataPolicyBuilder.build();
  }

  @Data
  @AllArgsConstructor
  static class MdOperatorData {
    String name;
    Object value;
  }

  @Data
  @AllArgsConstructor
  @NoArgsConstructor
  @Builder
  static class MdParamData {
    MetadataParameter metadataParameter;
    List<MdOperatorData> operators;
  }

  @Data
  @AllArgsConstructor
  @NoArgsConstructor
  @Builder
  static class EtPolicyData {
    List<MdParamData> metadataParameters;
  }

}
