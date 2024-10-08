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

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.oidc.oidfed.base.configuration.PolicyParameterFormats;
import se.oidc.oidfed.base.process.metadata.MetadataPolicyProcessor;
import se.oidc.oidfed.base.process.metadata.MetadataPolicySerializer;
import se.oidc.oidfed.base.process.metadata.PolicyOperatorFactory;
import se.oidc.oidfed.base.process.metadata.PolicyProcessingException;
import se.oidc.oidfed.base.process.metadata.impl.DefaultPolicyOperatorFactory;
import se.oidc.oidfed.base.process.metadata.impl.StandardMetadataPolicySerializer;
import se.oidc.oidfed.base.process.metadata.policyoperators.AddPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.DefaultPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.EssentialPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.OneOfPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.SubsetOfPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.SupersetOfPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.ValuePolicyOperator;
import se.oidc.oidfed.base.testdata.PolicyData;
import se.oidc.oidfed.base.utils.OidcUtils;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Metadata policy processor tests
 */
@Slf4j
class EntityTypeMetadataPolicyProcessorTest {

  private static MetadataPolicyProcessor policyProcessor;
  static PolicyOperatorFactory policyOperatorFactory;
  static MetadataPolicySerializer serializer;

  @BeforeAll
  static void init() {
    policyOperatorFactory = DefaultPolicyOperatorFactory.getInstance();
    policyProcessor = new MetadataPolicyProcessor();
    serializer = new StandardMetadataPolicySerializer(policyOperatorFactory,
        Arrays.stream(PolicyParameterFormats.values())
            .collect(
                Collectors.toMap(PolicyParameterFormats::getParameterName, PolicyParameterFormats::toMetadataParameter))
    );
  }

  @Test
  void policyTests() throws Exception {

    this.executePolicyTest("Client scope with value policy",
        "some_scope another_scope",
        List.of(new PolicyData(
            ValuePolicyOperator.OPERATOR_NAME, "openid")
        ),
        PolicyParameterFormats.scope,
        "openid"
    );

    this.executePolicyTest("Test add",
        "openid",
        List.of(new PolicyData(
            AddPolicyOperator.OPERATOR_NAME, "another_scope")
        ),
        PolicyParameterFormats.scope,
        "openid another_scope"
    );

    this.executePolicyTest("Test default",
        null,
        List.of(new PolicyData(
            DefaultPolicyOperator.OPERATOR_NAME, "openid")),
        PolicyParameterFormats.scope,
        "openid"
    );

    this.executePolicyTest("Test essential",
        null,
        List.of(new PolicyData(
            EssentialPolicyOperator.OPERATOR_NAME, true)
        ),
        PolicyParameterFormats.scope,
        PolicyProcessingException.class
    );

    this.executePolicyTest("Test one_of - Not matching",
        "openid",
        List.of(new PolicyData(OneOfPolicyOperator.OPERATOR_NAME, List.of("true", "scope"))
        ),
        PolicyParameterFormats.scope,
        PolicyProcessingException.class
    );

    this.executePolicyTest("Test one_of - matching",
        "issuer1",
        List.of(new PolicyData(OneOfPolicyOperator.OPERATOR_NAME, List.of("issuer1", "issuer2"))
        ),
        PolicyParameterFormats.issuer,
        "issuer1"
    );

    this.executePolicyTest("Test subset_of",
        List.of("code", "id_token"),
        List.of(
            new PolicyData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("code", "response_type")),
            new PolicyData(EssentialPolicyOperator.OPERATOR_NAME, true)
        ),
        PolicyParameterFormats.response_types_supported,
        List.of("code")
    );

    this.executePolicyTest("Test subset_of - empty - non essential",
        null,
        List.of(
            new PolicyData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("code", "response_type"))
        ),
        PolicyParameterFormats.response_types_supported, null
    );

    this.executePolicyTest("Test subset_of - empty - essential",
        List.of("my_response_type"),
        List.of(
            new PolicyData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("code", "response_type")),
            new PolicyData(EssentialPolicyOperator.OPERATOR_NAME, true)
        ),
        PolicyParameterFormats.response_types_supported,
        PolicyProcessingException.class
    );

    this.executePolicyTest("Test superset_of",
        List.of("code", "id_token", "response_type"),
        List.of(
            new PolicyData(SupersetOfPolicyOperator.OPERATOR_NAME, List.of("code", "response_type")),
            new PolicyData(
                EssentialPolicyOperator.OPERATOR_NAME, true)
        ),
        PolicyParameterFormats.response_types_supported,
        List.of("code", "id_token", "response_type")
    );

    this.executePolicyTest("Test superset_of - empty - non essential",
        null,
        List.of(
            new PolicyData(SupersetOfPolicyOperator.OPERATOR_NAME, List.of("code", "response_type"))),
        PolicyParameterFormats.response_types_supported,
        PolicyProcessingException.class
    );

    this.executePolicyTest("Test subset_of - mismatch - essential",
        List.of("my_response_type"),
        List.of(
            new PolicyData(SupersetOfPolicyOperator.OPERATOR_NAME, List.of("code", "response_type")),
            new PolicyData(EssentialPolicyOperator.OPERATOR_NAME, true)
        ),
        PolicyParameterFormats.response_types_supported,
        PolicyProcessingException.class
    );

    this.executePolicyTest("Malused one_of on array of values",
        List.of("code", "id_token"),
        List.of(new PolicyData(OneOfPolicyOperator.OPERATOR_NAME, List.of("code"))),
        PolicyParameterFormats.response_types_supported,
        PolicyProcessingException.class
    );

    this.executePolicyTest("Test boolean",
        true,
        List.of(new PolicyData(ValuePolicyOperator.OPERATOR_NAME, true)),
        PolicyParameterFormats.request_uri_parameter_supported,
        true
    );

    this.executePolicyTest("Test boolean - mismatch",
        true,
        List.of(new PolicyData(OneOfPolicyOperator.OPERATOR_NAME, List.of(false))),
        PolicyParameterFormats.request_uri_parameter_supported,
        PolicyProcessingException.class
    );

    this.executePolicyTest("Multiple modifiers",
        null,
        List.of(
            new PolicyData(ValuePolicyOperator.OPERATOR_NAME, List.of("openid", "other_scope")),
            new PolicyData(AddPolicyOperator.OPERATOR_NAME, List.of("next_scope")),
            new PolicyData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("openid", "next_scope"))
        ),
        PolicyParameterFormats.scopes_supported,
        PolicyProcessingException.class
    );

    this.executePolicyTest("Integer test",
        null,
        List.of(
            new PolicyData(ValuePolicyOperator.OPERATOR_NAME, List.of("openid", "other_scope")),
            new PolicyData(AddPolicyOperator.OPERATOR_NAME, List.of("next_scope")),
            new PolicyData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("openid", "next_scope"))
        ),
        PolicyParameterFormats.scopes_supported,
        PolicyProcessingException.class
    );

  }

  private void executePolicyTest(final String description, final Object value, final List<PolicyData> policyDataList,
      final PolicyParameterFormats parameter, final Object result) throws Exception {

    log.info(description);
    log.info("Testing policy value: {}", value);
    final MetadataParameterPolicy.MetadataParameterPolicyBuilder mppBuilder =
        MetadataParameterPolicy.builder(parameter.toMetadataParameter());
    for (final PolicyData policyData : policyDataList) {
      mppBuilder.add(policyData.getPolicy(), policyData.getValue());
    }
    final MetadataParameterPolicy metadataParameterPolicy = mppBuilder.build();
    final EntityTypeMetadataPolicy entityTypeMetadataPolicy = EntityTypeMetadataPolicy.builder()
        .addMetadataParameterPolicy(metadataParameterPolicy)
        .build();

    log.info("Testing against policy:\n{}",
        OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(
            serializer.toJsonObject(entityTypeMetadataPolicy)
        ));

    final Class<? extends Exception> exceptionClass;
    if (result instanceof Class<?>) {
      exceptionClass = (Class<? extends Exception>) result;
      final Exception exception =
          assertThrows(exceptionClass, () -> policyProcessor.processPolicyParam(value, metadataParameterPolicy));
      log.info("Thrown expected {} with message {}\n", exception.getClass().getSimpleName(), exception.getMessage());
      return;
    }

    final Object updatedValue = policyProcessor.processPolicyParam(value, metadataParameterPolicy);
    log.info("Policy processing result: {}", updatedValue);
    assertEquals(result, updatedValue);
  }
}
