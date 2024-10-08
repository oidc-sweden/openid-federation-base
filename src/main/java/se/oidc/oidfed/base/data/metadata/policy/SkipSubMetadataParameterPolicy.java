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
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import se.oidc.oidfed.base.configuration.MetadataParameter;
import se.oidc.oidfed.base.process.metadata.PolicyMergeException;
import se.oidc.oidfed.base.process.metadata.PolicyOperatorFactory;
import se.oidc.oidfed.base.process.metadata.PolicyProcessingException;
import se.oidc.oidfed.base.process.metadata.PolicyTranslationException;
import se.oidc.oidfed.base.process.metadata.impl.DefaultPolicyOperatorFactory;
import se.oidc.oidfed.base.process.metadata.policyoperators.PolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.SkipSubordinatesPolicyOperator;

import java.util.ArrayList;
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

  public SkipSubMetadataParameterPolicy(final MetadataParameter parameter,
      final Map<String, PolicyOperator> policyOperators) {
    super(parameter, policyOperators);
    this.skipSubordinates = false;
  }

  protected boolean skipSubordinates;

  @Override
  public MetadataParameterPolicy mergeWithSubordinate(final MetadataParameterPolicy subordinateMetadataParameterPolicy)
      throws PolicyMergeException, PolicyTranslationException, PolicyProcessingException {
    if (this.skipSubordinates) {
      log.debug("Policy for metadata parameter {} is set to skip_subordinates. Skipping merge",
          this.parameter.getName());
      return this;
    }
    if (subordinateMetadataParameterPolicy == null) {
      log.debug("Subordinate policy for metadata parameter {} is null. Skipping merge", this.parameter.getName());
      return this;
    }
    final SkipSubMetadataParameterPolicyBuilder builder = SkipSubMetadataParameterPolicy.builder(this.parameter);
    final List<String> allPolicyOperatorNames = new ArrayList<>(this.policyOperators.keySet());
    final Map<String, PolicyOperator> policyOperatorsToMerge = subordinateMetadataParameterPolicy.getPolicyOperators();
    policyOperatorsToMerge.keySet().stream()
        .filter(s -> !allPolicyOperatorNames.contains(s))
        .forEach(allPolicyOperatorNames::add);

    for (final String operatorName : allPolicyOperatorNames) {
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

  public static SkipSubMetadataParameterPolicyBuilder builder(final MetadataParameter parameter) {
    return new SkipSubMetadataParameterPolicyBuilder(parameter);
  }

  public static SkipSubMetadataParameterPolicyBuilder builder(final MetadataParameter parameter,
      final PolicyOperatorFactory policyOperatorFactory) {
    return new SkipSubMetadataParameterPolicyBuilder(parameter, policyOperatorFactory);
  }

  public static class SkipSubMetadataParameterPolicyBuilder
      extends MetadataParameterPolicy.MetadataParameterPolicyBuilder {

    public SkipSubMetadataParameterPolicyBuilder(final MetadataParameter parameter) {
      this(parameter, new DefaultPolicyOperatorFactory());
    }

    public SkipSubMetadataParameterPolicyBuilder(final MetadataParameter parameter,
        final PolicyOperatorFactory policyOperatorFactory) {
      super(parameter);
      this.metadataParameterPolicy = new SkipSubMetadataParameterPolicy();
      this.metadataParameterPolicy.setParameter(parameter);
      this.policyOperatorFactory = policyOperatorFactory;
    }

    @Override
    public MetadataParameterPolicyBuilder add(final String operatorName, final Object value)
        throws PolicyTranslationException, PolicyProcessingException {
      final PolicyOperator policyOperator = this.policyOperatorFactory.getPolicyOperator(
          operatorName, this.metadataParameterPolicy.getParameter().getValueType(), value);
      this.metadataParameterPolicy.getPolicyOperators().put(operatorName, policyOperator);
      // If the operator is skip_subordinates set to true, also set the skipSubordinates flag.
      if (operatorName.equals(SkipSubordinatesPolicyOperator.OPERATOR_NAME)) {
        this.skipSubordinates((Boolean) policyOperator.getPolicyOperatorValue());
      }
      return this;
    }

    public MetadataParameterPolicyBuilder skipSubordinates(final boolean skipSubordinates) {
      ((SkipSubMetadataParameterPolicy) this.metadataParameterPolicy).skipSubordinates = skipSubordinates;
      return this;
    }

  }

}
