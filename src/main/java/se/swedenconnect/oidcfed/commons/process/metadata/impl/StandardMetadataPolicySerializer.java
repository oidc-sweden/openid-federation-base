package se.swedenconnect.oidcfed.commons.process.metadata.impl;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.lang.NonNull;

import lombok.RequiredArgsConstructor;
import se.swedenconnect.oidcfed.commons.configuration.MetadataParameter;
import se.swedenconnect.oidcfed.commons.data.metadata.policy.MetadataParameterPolicy;
import se.swedenconnect.oidcfed.commons.data.metadata.policy.EntityTypeMetadataPolicy;
import se.swedenconnect.oidcfed.commons.process.metadata.MetadataPolicySerializer;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyOperatorFactory;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyProcessingException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyTranslationException;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.SkipSubordinatesPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.PolicyOperator;

/**
 * Metadata policy serializer using the current draft format. Serialization of policy for one Entity Type
 *
 * <p>
 * Note: This serializer does not distinguish between different types of Entities. This works as long
 * as different entity types do not use metadata parameters with the same name, but different value types.
 * </p>
 * <p>
 * If this is the case, then these Entity types must use different instances if this class adapted to their
 * metadata parameters and value types.
 * </p>
 */
@RequiredArgsConstructor
public class StandardMetadataPolicySerializer implements MetadataPolicySerializer {

  private final PolicyOperatorFactory policyOperatorFactory;
  private final Map<String, MetadataParameter> supportedMetadataParametersMap;

  @Override public Map<String, Object> toJsonObject(EntityTypeMetadataPolicy entityTypeMetadataPolicy) {
    Map<String, Object> metadataPolicyObject = new HashMap<>();
    Map<String, MetadataParameterPolicy> entityTypeMetadata = entityTypeMetadataPolicy.getMetadataParameterPolicyMap();
    Set<String> metadataParameterKeySet = entityTypeMetadata.keySet();
    for (String metadataParameter : metadataParameterKeySet) {
      Map<String, Object> policyOperatorsObject = new HashMap<>();
      MetadataParameterPolicy metadataParameterPolicy = entityTypeMetadata.get(metadataParameter);
      Map<String, PolicyOperator> operators = metadataParameterPolicy.getPolicyOperators();
      Set<String> operatorKeySet = operators.keySet();
      for (String operatorName : operatorKeySet) {
        policyOperatorsObject.put(operatorName, operators.get(operatorName).getPolicyOperatorValue());
      }
      // If skip subordinates boolean is set, make sure that the corresponding policy operator is included
      if (metadataParameterPolicy.isSkipSubordinates()) {
        policyOperatorsObject.put(SkipSubordinatesPolicyOperator.OPERATOR_NAME, Boolean.TRUE);
      }
      metadataPolicyObject.put(metadataParameter, policyOperatorsObject);
    }
    return metadataPolicyObject;
  }

  @Override public EntityTypeMetadataPolicy fromJsonObject(@NonNull Map<String, Object> jsonObject,
    @NonNull List<String> criticalOperators) throws PolicyProcessingException, PolicyTranslationException {

    EntityTypeMetadataPolicy.EntityTypeMetadataPolicyBuilder entityTypeMetadataPolicyBuilder = EntityTypeMetadataPolicy.builder();
    Set<String> objectKeySet = jsonObject.keySet();
    for (String metadataParameterName : objectKeySet) {
      if (!supportedMetadataParametersMap.containsKey(metadataParameterName)) {
        throw new PolicyProcessingException("Unsupported metadata parameter: " + metadataParameterName);
      }
      MetadataParameter metadataParameter = supportedMetadataParametersMap.get(metadataParameterName);
      MetadataParameterPolicy.MetadataParameterPolicyBuilder parameterPolicyBuilder = MetadataParameterPolicy.builder(
        metadataParameter);
      Object parameterObj = jsonObject.get(metadataParameterName);
      Map<String, Object> metadataParameterObj;
      try {
        metadataParameterObj = (Map<String, Object>) parameterObj;
      }
      catch (Exception ex) {
        throw new PolicyProcessingException("Illegal content in entity metadata policy object");
      }
      Set<String> operatorKeySet = metadataParameterObj.keySet();
      for (String operatorName : operatorKeySet) {
        PolicyOperator policyOperator = policyOperatorFactory.getPolicyOperator(
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
        // Check if this is a skip_subordinates policy operator
        if (operatorName.equals(SkipSubordinatesPolicyOperator.OPERATOR_NAME)) {
          if (((SkipSubordinatesPolicyOperator) policyOperator).getPolicyOperatorValue()) {
            parameterPolicyBuilder.skipSubordinates(true);
          }
        }
        // Add policy operator
        parameterPolicyBuilder.add(policyOperator);
      }
      entityTypeMetadataPolicyBuilder.addMetadataParameterPolicy(parameterPolicyBuilder.build());
    }
    return entityTypeMetadataPolicyBuilder.build();
  }

}

