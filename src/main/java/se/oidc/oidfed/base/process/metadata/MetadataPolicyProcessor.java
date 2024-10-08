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
package se.oidc.oidfed.base.process.metadata;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import lombok.RequiredArgsConstructor;
import se.oidc.oidfed.base.process.metadata.policyoperators.AddPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.DefaultPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.PolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.SubsetOfPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.ValuePolicyOperator;
import se.oidc.oidfed.base.data.metadata.policy.EntityTypeMetadataPolicy;
import se.oidc.oidfed.base.data.metadata.policy.MetadataParameterPolicy;
import se.oidc.oidfed.base.utils.OidcUtils;

/**
 * Processor that updates OpenID federation metadata based on a metadata policy
 */
@RequiredArgsConstructor
public class MetadataPolicyProcessor {

  /**
   * Process metadata and apply changes mandated by a provided metadata policy
   *
   * @param metadata the metadata to process
   * @param entityTypeMetadataPolicy the metadata policy
   * @return processed metadata that is modified according to the policy
   * @throws PolicyTranslationException error parsing the metadata policy
   * @throws PolicyProcessingException error processing the metadata according to the policy
   */
  Map<String, Object> applyMetadataPolicy(Map<String, Object> metadata, EntityTypeMetadataPolicy entityTypeMetadataPolicy)
    throws PolicyTranslationException, PolicyProcessingException {
    Map<String, Object> processedMetadata = new HashMap<>(metadata);
    Map<String, MetadataParameterPolicy> metadataParameterPolicyMap = entityTypeMetadataPolicy.getMetadataParameterPolicyMap();
    Set<String> metadataParamSet = metadataParameterPolicyMap.keySet();

    //Process each policy param set
    for (String metadataParameter : metadataParamSet) {
      Object updatedValue = processPolicyParam(metadata.get(metadataParameter), metadataParameterPolicyMap.get(metadataParameter));
      if (updatedValue != null) {
        processedMetadata.put(metadataParameter, updatedValue);
      }
      else {
        processedMetadata.remove(metadataParameter);
      }
    }
    return processedMetadata;
  }

  public Object processPolicyParam(Object value, MetadataParameterPolicy metadataParameterPolicy)
    throws PolicyProcessingException, PolicyTranslationException {

    // First run all modifiers as modifiers
    List<String> updatedValue = modifyMetadataValue(value, metadataParameterPolicy);

    // Validate that the result meets all policy requirements
    validateMetadataValue(updatedValue, metadataParameterPolicy);


    return OidcUtils.convertToValueObject(updatedValue, metadataParameterPolicy.getParameter().getValueType());
  }

  /**
   * Policy modifiers are applied in the following order
   * - value
   * - add
   * - default
   * - subset_of
   * - superset_of
   *
   * @param value the value to modify
   * @param metadataParameterPolicy policy rules
   * @return updated metadata value as list of String parameters
   * @throws PolicyProcessingException error processing policy
   * @throws PolicyTranslationException error processing data type translations
   */
  public List<String> modifyMetadataValue(Object value, MetadataParameterPolicy metadataParameterPolicy)
    throws PolicyProcessingException, PolicyTranslationException {

    Map<String, PolicyOperator> policyOperators = metadataParameterPolicy.getPolicyOperators();

    String valueType = Optional.ofNullable(metadataParameterPolicy.getParameter().getValueType())
      .orElseThrow(() -> new PolicyProcessingException("Metadata policy has no defined value type"));

    // Make sure we have a non-empty and extendable value item list
    List<String> updatedValue = new ArrayList<>(
      Optional.ofNullable(
          OidcUtils.convertToStringList(value, valueType))
        .orElse(List.of())
    );

    // Process value modifier
    updatedValue = processValueModifier(ValuePolicyOperator.OPERATOR_NAME, updatedValue, policyOperators);
    updatedValue = processValueModifier(AddPolicyOperator.OPERATOR_NAME, updatedValue, policyOperators);
    updatedValue = processValueModifier(DefaultPolicyOperator.OPERATOR_NAME, updatedValue, policyOperators);
    updatedValue = processValueModifier(SubsetOfPolicyOperator.OPERATOR_NAME, updatedValue, policyOperators);

    // Get the rest of the operators
    List<String> otherPolicyOperatorNames = policyOperators.keySet().stream()
      .filter(operator -> !ValuePolicyOperator.OPERATOR_NAME.equals(operator))
      .filter(operator -> !AddPolicyOperator.OPERATOR_NAME.equals(operator))
      .filter(operator -> !DefaultPolicyOperator.OPERATOR_NAME.equals(operator))
      .filter(operator -> !SubsetOfPolicyOperator.OPERATOR_NAME.equals(operator))
      .toList();

    for (String operatorName : otherPolicyOperatorNames) {
      updatedValue = processValueModifier(operatorName, updatedValue, policyOperators);
    }
    return updatedValue;
  }

  private List<String> processValueModifier(String operatorName, List<String> value, Map<String, PolicyOperator> policyOperators) {
    if (!policyOperators.containsKey(operatorName)){
      return value;
    }
    return policyOperators.get(operatorName).getModifiedMetadataValues(value);
  }

  /**
   * Validate a policy value converted to a string list against a set of normalized policy modifiers. An empty
   * value is represented by an empty string list.
   *
   * @param value metadata value converted to string list
   * @param metadataParameterPolicy metadata parameter policy (including value check directives)
   * @throws PolicyProcessingException Error encountered applying policy rules to the metadata value
   */
  public void validateMetadataValue(final List<String> value, final MetadataParameterPolicy metadataParameterPolicy)
    throws PolicyProcessingException {

    List<String> metadataValue = Optional.ofNullable(value).orElse(new ArrayList<>());

    Map<String, PolicyOperator> policyOperators = metadataParameterPolicy.getPolicyOperators();
    for (String operatorName : policyOperators.keySet()) {
      if (!policyOperators.get(operatorName).isMetadataValid(metadataValue)) {
        throw new PolicyProcessingException("Metadata value does not match the policy operator: " + operatorName);
      }
    }
  }

}
