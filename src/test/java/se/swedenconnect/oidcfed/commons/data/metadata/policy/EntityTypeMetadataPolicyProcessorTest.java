package se.swedenconnect.oidcfed.commons.data.metadata.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.oidcfed.commons.configuration.PolicyParameterFormats;
import se.swedenconnect.oidcfed.commons.process.metadata.MetadataPolicySerializer;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyOperatorFactory;
import se.swedenconnect.oidcfed.commons.process.metadata.impl.DefaultPolicyOperatorFactory;
import se.swedenconnect.oidcfed.commons.process.metadata.impl.StandardMetadataPolicySerializer;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.AddPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.DefaultPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.EssentialPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.OneOfPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.SubsetOfPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.SupersetOfPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.ValuePolicyOperator;
import se.swedenconnect.oidcfed.commons.testdata.PolicyData;
import se.swedenconnect.oidcfed.commons.utils.OidcUtils;
import se.swedenconnect.oidcfed.commons.process.metadata.MetadataPolicyProcessor;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyProcessingException;

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

    executePolicyTest("Client scope with value policy",
      "some_scope another_scope",
      List.of(new PolicyData(
        ValuePolicyOperator.OPERATOR_NAME, "openid")
      ),
      PolicyParameterFormats.scope,
      "openid"
    );

    executePolicyTest("Test add",
      "openid",
      List.of(new PolicyData(
        AddPolicyOperator.OPERATOR_NAME, "another_scope")
      ),
      PolicyParameterFormats.scope,
      "openid another_scope"
    );

    executePolicyTest("Test default",
      null,
      List.of(new PolicyData(
        DefaultPolicyOperator.OPERATOR_NAME, "openid")),
      PolicyParameterFormats.scope,
      "openid"
    );

    executePolicyTest("Test essential",
      null,
      List.of(new PolicyData(
        EssentialPolicyOperator.OPERATOR_NAME, true)
      ),
      PolicyParameterFormats.scope,
      PolicyProcessingException.class
    );

    executePolicyTest("Test one_of - Not matching",
      "openid",
      List.of(new PolicyData(OneOfPolicyOperator.OPERATOR_NAME, List.of("true", "scope"))
      ),
      PolicyParameterFormats.scope,
      PolicyProcessingException.class
    );

    executePolicyTest("Test one_of - matching",
      "issuer1",
      List.of(new PolicyData(OneOfPolicyOperator.OPERATOR_NAME, List.of("issuer1", "issuer2"))
      ),
      PolicyParameterFormats.issuer,
      "issuer1"
    );

    executePolicyTest("Test subset_of",
      List.of("code", "id_token"),
      List.of(
        new PolicyData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("code", "response_type")),
        new PolicyData(EssentialPolicyOperator.OPERATOR_NAME, true)
      ),
      PolicyParameterFormats.response_types_supported,
      List.of("code")
    );

    executePolicyTest("Test subset_of - empty - non essential",
      null,
      List.of(
        new PolicyData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("code", "response_type"))
      ),
      PolicyParameterFormats.response_types_supported, null
    );

    executePolicyTest("Test subset_of - empty - essential",
      List.of("my_response_type"),
      List.of(
        new PolicyData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("code", "response_type")),
        new PolicyData(EssentialPolicyOperator.OPERATOR_NAME, true)
      ),
      PolicyParameterFormats.response_types_supported,
      PolicyProcessingException.class
    );

    executePolicyTest("Test superset_of",
      List.of("code", "id_token", "response_type"),
      List.of(
        new PolicyData(SupersetOfPolicyOperator.OPERATOR_NAME, List.of("code", "response_type")),
        new PolicyData(
          EssentialPolicyOperator.OPERATOR_NAME, true)
      ),
      PolicyParameterFormats.response_types_supported,
      List.of("code", "id_token", "response_type")
    );

    executePolicyTest("Test superset_of - empty - non essential",
      null,
      List.of(
        new PolicyData(SupersetOfPolicyOperator.OPERATOR_NAME, List.of("code", "response_type"))),
      PolicyParameterFormats.response_types_supported,
      PolicyProcessingException.class
    );

    executePolicyTest("Test subset_of - mismatch - essential",
      List.of("my_response_type"),
      List.of(
        new PolicyData(SupersetOfPolicyOperator.OPERATOR_NAME, List.of("code", "response_type")),
        new PolicyData(EssentialPolicyOperator.OPERATOR_NAME, true)
      ),
      PolicyParameterFormats.response_types_supported,
      PolicyProcessingException.class
    );

    executePolicyTest("Malused one_of on array of values",
      List.of("code", "id_token"),
      List.of(new PolicyData(OneOfPolicyOperator.OPERATOR_NAME, List.of("code"))),
      PolicyParameterFormats.response_types_supported,
      PolicyProcessingException.class
    );

    executePolicyTest("Test boolean",
      true,
      List.of(new PolicyData(ValuePolicyOperator.OPERATOR_NAME, true)),
      PolicyParameterFormats.request_uri_parameter_supported,
      true
    );

    executePolicyTest("Test boolean - mismatch",
      true,
      List.of(new PolicyData(OneOfPolicyOperator.OPERATOR_NAME, List.of(false))),
      PolicyParameterFormats.request_uri_parameter_supported,
      PolicyProcessingException.class
    );

    executePolicyTest("Multiple modifiers",
      null,
      List.of(
        new PolicyData(ValuePolicyOperator.OPERATOR_NAME, List.of("openid", "other_scope")),
        new PolicyData(AddPolicyOperator.OPERATOR_NAME, List.of("next_scope")),
        new PolicyData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("openid", "next_scope"))
      ),
      PolicyParameterFormats.scopes_supported,
      PolicyProcessingException.class
    );

    executePolicyTest("Integer test",
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

  private void executePolicyTest(String description, Object value, List<PolicyData> policyDataList,
    PolicyParameterFormats parameter, Object result) throws Exception {

    log.info(description);
    log.info("Testing policy value: {}", value);
    MetadataParameterPolicy.MetadataParameterPolicyBuilder mppBuilder = MetadataParameterPolicy.builder(parameter.toMetadataParameter());
    for (PolicyData policyData : policyDataList) {
      mppBuilder.add(policyData.getPolicy(), policyData.getValue());
    }
    MetadataParameterPolicy metadataParameterPolicy = mppBuilder.build();
    EntityTypeMetadataPolicy entityTypeMetadataPolicy = EntityTypeMetadataPolicy.builder()
      .addMetadataParameterPolicy(metadataParameterPolicy)
      .build();

    log.info("Testing against policy:\n{}",
      OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(
        serializer.toJsonObject(entityTypeMetadataPolicy)
      ));

    Class<? extends Exception> exceptionClass;
    if (result instanceof Class<?>) {
      exceptionClass = (Class<? extends Exception>) result;
      Exception exception = assertThrows(exceptionClass, () -> {
        policyProcessor.processPolicyParam(value, metadataParameterPolicy);
      });
      log.info("Thrown expected {} with message {}\n", exception.getClass().getSimpleName(), exception.getMessage());
      return;
    }

    Object updatedValue = policyProcessor.processPolicyParam(value, metadataParameterPolicy);
    log.info("Policy processing result: {}", updatedValue);
    assertEquals(result, updatedValue);
  }
}