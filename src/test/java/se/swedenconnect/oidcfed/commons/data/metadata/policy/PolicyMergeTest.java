package se.swedenconnect.oidcfed.commons.data.metadata.policy;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.oidcfed.commons.configuration.MetadataParameter;
import se.swedenconnect.oidcfed.commons.configuration.PolicyParameterFormats;
import se.swedenconnect.oidcfed.commons.process.metadata.MetadataPolicySerializer;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyOperatorFactory;
import se.swedenconnect.oidcfed.commons.process.metadata.impl.DefaultPolicyOperatorFactory;
import se.swedenconnect.oidcfed.commons.process.metadata.impl.StandardMetadataPolicySerializer;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.OneOfPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.PolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.SkipSubordinatesPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.SubsetOfPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.SupersetOfPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.ValuePolicyOperator;
import se.swedenconnect.oidcfed.commons.utils.OidcUtils;

/**
 * Testing policy merge
 */
@Slf4j
public class PolicyMergeTest {

  static PolicyOperatorFactory policyOperatorFactory;
  static MetadataPolicySerializer serializer;

  @BeforeAll
  static void init() {
    policyOperatorFactory = DefaultPolicyOperatorFactory.getInstance();
    serializer = new StandardMetadataPolicySerializer(policyOperatorFactory,
      Arrays.stream(PolicyParameterFormats.values())
        .collect(
          Collectors.toMap(PolicyParameterFormats::getParameterName, PolicyParameterFormats::toMetadataParameter))
    );
  }

  @Test
  void mergeTest() throws Exception {

    testPolicyMerge("Basic merge",
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

    testPolicyMerge("Different operators merge",
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

    testPolicyMerge("Merge with skip operator",
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

    testPolicyMerge("Merge with different parameter policy",
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
              new MdOperatorData(OneOfPolicyOperator.OPERATOR_NAME, List.of("Issuer name", "Issuer alt name"))
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
                new MdOperatorData(OneOfPolicyOperator.OPERATOR_NAME, List.of("Issuer name", "Issuer alt name"))
              )).build()
          )).build()
    );

    testPolicyMerge("Merge with different parameter policy with skip",
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
              new MdOperatorData(OneOfPolicyOperator.OPERATOR_NAME, List.of("Issuer name", "Issuer alt name"))
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
                new MdOperatorData(OneOfPolicyOperator.OPERATOR_NAME, List.of("Issuer name", "Issuer alt name"))
              )).build()
          )).build()
    );

    testPolicyMerge("Merge with Null policy",
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
                new MdOperatorData(OneOfPolicyOperator.OPERATOR_NAME, List.of("Issuer name", "Issuer alt name"))
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
                new MdOperatorData(OneOfPolicyOperator.OPERATOR_NAME, List.of("Issuer name", "Issuer alt name"))
              )).build()
          )).build()
    );



  }

  private void testPolicyMerge(String message, EtPolicyData superior, EtPolicyData subordinate, EtPolicyData expected)
    throws Exception {
    log.info(message);
    EntityTypeMetadataPolicy superiorPolicy = getEtMetadataPolicy(superior);
    log.info("Superior policy: \n{}", OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(
      serializer.toJsonObject(superiorPolicy)
    ));
    EntityTypeMetadataPolicy subordinatePolicy = getEtMetadataPolicy(subordinate);
    log.info("Subordinate policy: \n{}", subordinatePolicy == null
      ? null
      : OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(
      serializer.toJsonObject(subordinatePolicy))
    );

    EntityTypeMetadataPolicy mergedPolicy = superiorPolicy.mergeWithSubordinate(subordinatePolicy);
    log.info("Merged policy: \n{}", OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(
      serializer.toJsonObject(mergedPolicy)
    ));

    EntityTypeMetadataPolicy expectedPolicy = getEtMetadataPolicy(expected);
    Map<String, MetadataParameterPolicy> mergedPolicyMap = mergedPolicy.getMetadataParameterPolicyMap();
    Map<String, MetadataParameterPolicy> expectedPolicyMap = expectedPolicy.getMetadataParameterPolicyMap();
    assertEquals(expectedPolicyMap.keySet().size(), mergedPolicyMap.keySet().size(), "Parameter count mismatch");
    assertTrue(expectedPolicyMap.keySet().stream().allMatch(mergedPolicyMap::containsKey), "Parameter names mismatch");
    for (String parameterName : expectedPolicyMap.keySet()) {
      MetadataParameterPolicy expectedParameterPolicy = expectedPolicyMap.get(parameterName);
      MetadataParameterPolicy mergedParameterPolicy = mergedPolicyMap.get(parameterName);
      assertEquals(expectedParameterPolicy.isSkipSubordinates(), mergedParameterPolicy.isSkipSubordinates(),
        "Skip subordinates mismatch");
      Map<String, PolicyOperator> expectedOperators = expectedParameterPolicy.getPolicyOperators();
      Map<String, PolicyOperator> mergedOperators = mergedParameterPolicy.getPolicyOperators();
      assertEquals(expectedOperators.keySet().size(), mergedOperators.keySet().size(),
        "Policy operator count mismatch");
      assertTrue(expectedOperators.keySet().stream().allMatch(mergedOperators::containsKey),
        "Policy operator names mismatch");
      for (String operatorName : expectedOperators.keySet()) {
        PolicyOperator expectedOperator = expectedOperators.get(operatorName);
        PolicyOperator mergedOperator = mergedOperators.get(operatorName);
        assertEquals(expectedOperator.getName(), mergedOperator.getName(), "Operator name mismatch");
        assertEquals(expectedOperator.getPolicyOperatorValue(), mergedOperator.getPolicyOperatorValue(),
          "Operator value mismatch");
      }
    }
    log.info("Merge test complete\n");
  }

  private EntityTypeMetadataPolicy getEtMetadataPolicy(EtPolicyData etPolicyData) throws Exception {

    if (etPolicyData == null) {
      return null;
    }

    EntityTypeMetadataPolicy.EntityTypeMetadataPolicyBuilder entityTypeMetadataPolicyBuilder = EntityTypeMetadataPolicy.builder();
    for (MdParamData mdParamData : etPolicyData.getMetadataParameters()) {
      MetadataParameterPolicy.MetadataParameterPolicyBuilder parameterPolicyBuilder = MetadataParameterPolicy.builder(
        mdParamData.getMetadataParameter());
      for (MdOperatorData operatorData : mdParamData.getOperators()) {
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
