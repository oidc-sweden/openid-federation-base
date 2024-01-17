package se.swedenconnect.oidcfed.commons.data.metadata.policy;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.oidcfed.commons.configuration.MetadataParameter;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyMergeException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyOperatorFactory;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyProcessingException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyTranslationException;
import se.swedenconnect.oidcfed.commons.process.metadata.impl.DefaultPolicyOperatorFactory;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.PolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.SkipSubordinatesPolicyOperator;

/**
 * Metadata policy parameter
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Slf4j
public class MetadataParameterPolicy {

  public MetadataParameterPolicy(MetadataParameter parameter, Map<String, PolicyOperator> policyOperators) {
    this.parameter = parameter;
    this.policyOperators = policyOperators;
    this.skipSubordinates = false;
  }

  private MetadataParameter parameter;
  private boolean skipSubordinates;
  private Map<String, PolicyOperator> policyOperators = new HashMap<>();

  public MetadataParameterPolicy mergeWithSubordinate(MetadataParameterPolicy subordinateMetadataParameterPolicy)
    throws PolicyMergeException, PolicyTranslationException, PolicyProcessingException {
    if (skipSubordinates) {
      log.debug("Policy for metadata parameter {} is set to skip_subordinates. Skipping merge",
        this.parameter.getName());
      return this;
    }
    if (subordinateMetadataParameterPolicy == null) {
      log.debug("Subordinate policy for metadata parameter {} is null. Skipping merge", this.parameter.getName());
      return this;
    }
    MetadataParameterPolicyBuilder builder = MetadataParameterPolicy.builder(this.parameter);
    List<String> allPolicyOperatorNames = new ArrayList<>(this.policyOperators.keySet());
    Map<String, PolicyOperator> policyOperatorsToMerge = subordinateMetadataParameterPolicy.getPolicyOperators();
    policyOperatorsToMerge.keySet().stream()
      .filter(s -> !allPolicyOperatorNames.contains(s))
      .forEach(allPolicyOperatorNames::add);

    for (String operatorName : allPolicyOperatorNames) {
      if (!this.policyOperators.containsKey(operatorName)) {
        // Operator is only present in merged policy. Add this
        builder.add(policyOperatorsToMerge.get(operatorName));
        continue;
      }
      if (!policyOperatorsToMerge.containsKey(operatorName)) {
        // Operator is only present in this policy. Add this
        builder.add(this.policyOperators.get(operatorName));
        continue;
      }
      // Operator is present in both policies. Merge them
      builder.add(
        this.policyOperators.get(operatorName).mergeWithSubordinate(policyOperatorsToMerge.get(operatorName)));
    }
    return builder.build();
  }

  public static MetadataParameterPolicyBuilder builder(MetadataParameter parameter) {
    return new MetadataParameterPolicyBuilder(parameter);
  }

  public static MetadataParameterPolicyBuilder builder(MetadataParameter parameter,
    PolicyOperatorFactory policyOperatorFactory) {
    return new MetadataParameterPolicyBuilder(parameter, policyOperatorFactory);
  }

  public static class MetadataParameterPolicyBuilder {

    MetadataParameterPolicy metadataParameterPolicy;
    PolicyOperatorFactory policyOperatorFactory;

    public MetadataParameterPolicyBuilder(MetadataParameter parameter) {
      this(parameter, new DefaultPolicyOperatorFactory());
    }

    public MetadataParameterPolicyBuilder(MetadataParameter parameter, PolicyOperatorFactory policyOperatorFactory) {
      this.metadataParameterPolicy = new MetadataParameterPolicy();
      this.metadataParameterPolicy.setParameter(parameter);
      this.policyOperatorFactory = policyOperatorFactory;
    }

    public MetadataParameterPolicyBuilder add(PolicyOperator policyOperator) {
      metadataParameterPolicy.getPolicyOperators().put(policyOperator.getName(), policyOperator);
      return this;
    }

    public MetadataParameterPolicyBuilder add(String operatorName, Object value)
      throws PolicyTranslationException, PolicyProcessingException {
      PolicyOperator policyOperator = policyOperatorFactory.getPolicyOperator(
        operatorName, metadataParameterPolicy.getParameter().getValueType(), value);
      metadataParameterPolicy.getPolicyOperators().put(operatorName, policyOperator);
      // If the operator is skip_subordinates set to true, also set the skipSubordinates flag.
      if (operatorName.equals(SkipSubordinatesPolicyOperator.OPERATOR_NAME)) {
        skipSubordinates((Boolean)policyOperator.getPolicyOperatorValue());
      }
      return this;
    }

    public MetadataParameterPolicyBuilder skipSubordinates(boolean skipSubordinates) {
      metadataParameterPolicy.skipSubordinates = skipSubordinates;
      return this;
    }

    public MetadataParameterPolicy build() {
      return this.metadataParameterPolicy;
    }
  }

}
