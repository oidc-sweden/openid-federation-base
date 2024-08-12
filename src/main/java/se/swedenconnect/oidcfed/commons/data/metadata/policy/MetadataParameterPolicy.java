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
import se.swedenconnect.oidcfed.commons.configuration.ValueType;
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
@Slf4j
public class MetadataParameterPolicy {

  public MetadataParameterPolicy(MetadataParameter parameter, Map<String, PolicyOperator> policyOperators) {
    this.parameter = parameter;
    this.policyOperators = policyOperators;
  }

  protected MetadataParameter parameter;
  protected Map<String, PolicyOperator> policyOperators = new HashMap<>();

  public MetadataParameterPolicy mergeWithSubordinate(MetadataParameterPolicy subordinateMetadataParameterPolicy)
    throws PolicyMergeException, PolicyTranslationException, PolicyProcessingException {
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
        // Operator is only present in merged policy. Add that
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

  public static MetadataParameterPolicyBuilder builder(MetadataParameter parameter) throws PolicyTranslationException {
    if (parameter.getValueType().equals(ValueType.OBJECT)) {
      throw new PolicyTranslationException("Metadata policy is not allowed for metadata parameters holding JSON objects");
    }
    return new MetadataParameterPolicyBuilder(parameter);
  }

  public static MetadataParameterPolicyBuilder builder(MetadataParameter parameter,
    PolicyOperatorFactory policyOperatorFactory) {
    return new MetadataParameterPolicyBuilder(parameter, policyOperatorFactory);
  }

  public static class MetadataParameterPolicyBuilder {

    protected MetadataParameterPolicy metadataParameterPolicy;
    protected PolicyOperatorFactory policyOperatorFactory;

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
      return this;
    }

    public MetadataParameterPolicyBuilder skipSubordinates(boolean skipSubordinates) {
      throw new IllegalArgumentException("Skip subordinates is not supported");
    }

    public MetadataParameterPolicy build() {
      return this.metadataParameterPolicy;
    }
  }

}
