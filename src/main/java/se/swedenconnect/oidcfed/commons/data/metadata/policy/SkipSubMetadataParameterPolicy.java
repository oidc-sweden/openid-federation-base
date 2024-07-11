package se.swedenconnect.oidcfed.commons.data.metadata.policy;

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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Metadata policy parameter
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Slf4j
public class SkipSubMetadataParameterPolicy extends MetadataParameterPolicy {

  public SkipSubMetadataParameterPolicy(MetadataParameter parameter, Map<String, PolicyOperator> policyOperators) {
    super(parameter, policyOperators);
    this.skipSubordinates = false;
  }

  protected boolean skipSubordinates;

  @Override
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
    SkipSubMetadataParameterPolicyBuilder builder = SkipSubMetadataParameterPolicy.builder(this.parameter);
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

  public static SkipSubMetadataParameterPolicyBuilder builder(MetadataParameter parameter) {
    return new SkipSubMetadataParameterPolicyBuilder(parameter);
  }

  public static SkipSubMetadataParameterPolicyBuilder builder(MetadataParameter parameter,
    PolicyOperatorFactory policyOperatorFactory) {
    return new SkipSubMetadataParameterPolicyBuilder(parameter, policyOperatorFactory);
  }

  public static class SkipSubMetadataParameterPolicyBuilder extends MetadataParameterPolicy.MetadataParameterPolicyBuilder {

    public SkipSubMetadataParameterPolicyBuilder(MetadataParameter parameter) {
      this(parameter, new DefaultPolicyOperatorFactory());
    }

    public SkipSubMetadataParameterPolicyBuilder(MetadataParameter parameter, PolicyOperatorFactory policyOperatorFactory) {
      super(parameter);
      this.metadataParameterPolicy = new SkipSubMetadataParameterPolicy();
      this.metadataParameterPolicy.setParameter(parameter);
      this.policyOperatorFactory = policyOperatorFactory;
    }

    @Override
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
      ((SkipSubMetadataParameterPolicy)metadataParameterPolicy).skipSubordinates = skipSubordinates;
      return this;
    }

  }

}
