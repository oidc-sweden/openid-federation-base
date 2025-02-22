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
package se.oidc.oidfed.base.process.metadata.impl;

import jakarta.annotation.Nonnull;
import lombok.RequiredArgsConstructor;
import se.oidc.oidfed.base.configuration.MetadataParameter;
import se.oidc.oidfed.base.configuration.ValueType;
import se.oidc.oidfed.base.data.metadata.policy.EntityTypeMetadataPolicy;
import se.oidc.oidfed.base.data.metadata.policy.MetadataParameterPolicy;
import se.oidc.oidfed.base.process.metadata.MetadataPolicySerializer;
import se.oidc.oidfed.base.process.metadata.PolicyOperatorFactory;
import se.oidc.oidfed.base.process.metadata.PolicyProcessingException;
import se.oidc.oidfed.base.process.metadata.PolicyTranslationException;
import se.oidc.oidfed.base.process.metadata.policyoperators.PolicyOperator;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Metadata policy serializer using the current draft format. Serialization of policy for one Entity Type
 *
 * <p>
 * Note: This serializer does not distinguish between different types of Entities. This works as long as different
 * entity types do not use metadata parameters with the same name, but different value types.
 * </p>
 * <p>
 * If this is the case, then these Entity types must use different instances if this class adapted to their metadata
 * parameters and value types.
 * </p>
 */
@RequiredArgsConstructor
public class StandardMetadataPolicySerializer implements MetadataPolicySerializer {

  private final PolicyOperatorFactory policyOperatorFactory;
  private final Map<String, MetadataParameter> supportedMetadataParametersMap;

  @Override
  public Map<String, Object> toJsonObject(final EntityTypeMetadataPolicy entityTypeMetadataPolicy) {
    final Map<String, Object> metadataPolicyObject = new HashMap<>();
    final Map<String, MetadataParameterPolicy> entityTypeMetadata =
        entityTypeMetadataPolicy.getMetadataParameterPolicyMap();
    final Set<String> metadataParameterKeySet = entityTypeMetadata.keySet();
    for (final String metadataParameter : metadataParameterKeySet) {
      final Map<String, Object> policyOperatorsObject = new HashMap<>();
      final MetadataParameterPolicy metadataParameterPolicy = entityTypeMetadata.get(metadataParameter);
      final Map<String, PolicyOperator> operators = metadataParameterPolicy.getPolicyOperators();
      final Set<String> operatorKeySet = operators.keySet();
      for (final String operatorName : operatorKeySet) {
        policyOperatorsObject.put(operatorName, operators.get(operatorName).getPolicyOperatorValue());
      }
      metadataPolicyObject.put(metadataParameter, policyOperatorsObject);
    }
    return metadataPolicyObject;
  }

  @Override
  public EntityTypeMetadataPolicy fromJsonObject(@Nonnull final Map<String, Object> jsonObject,
      @Nonnull final List<String> criticalOperators) throws PolicyProcessingException, PolicyTranslationException {

    final EntityTypeMetadataPolicy.EntityTypeMetadataPolicyBuilder entityTypeMetadataPolicyBuilder =
        EntityTypeMetadataPolicy.builder();
    final Set<String> objectKeySet = jsonObject.keySet();
    for (final String metadataParameterName : objectKeySet) {
      if (!this.supportedMetadataParametersMap.containsKey(metadataParameterName)) {
        throw new PolicyProcessingException("Unsupported metadata parameter: " + metadataParameterName);
      }
      final MetadataParameter metadataParameter = this.supportedMetadataParametersMap.get(metadataParameterName);
      if (metadataParameter.getValueType().equals(ValueType.OBJECT)) {
        throw new PolicyProcessingException(
            "Metadata policy is not allowed for metadata parameters that contains a JSON object value");
      }
      final MetadataParameterPolicy.MetadataParameterPolicyBuilder parameterPolicyBuilder =
          MetadataParameterPolicy.builder(
              metadataParameter);
      final Object parameterObj = jsonObject.get(metadataParameterName);
      final Map<String, Object> metadataParameterObj;
      try {
        metadataParameterObj = (Map<String, Object>) parameterObj;
      }
      catch (final Exception ex) {
        throw new PolicyProcessingException("Illegal content in entity metadata policy object");
      }
      final Set<String> operatorKeySet = metadataParameterObj.keySet();
      for (final String operatorName : operatorKeySet) {
        final PolicyOperator policyOperator = this.policyOperatorFactory.getPolicyOperator(
            operatorName, metadataParameter.getValueType(),
            metadataParameterObj.get(operatorName));
        if (policyOperator == null) {
          // This policy operator was not recognized. Check for critical
          if (criticalOperators.contains(operatorName)) {
            throw new PolicyProcessingException("Unable to handle critical policy operator: " + operatorName);
          }
          // Ignoring unsupported non-critical policy operator
          continue;
        }
        // Add policy operator
        parameterPolicyBuilder.add(policyOperator);
      }
      entityTypeMetadataPolicyBuilder.addMetadataParameterPolicy(parameterPolicyBuilder.build());
    }
    return entityTypeMetadataPolicyBuilder.build();
  }

}
