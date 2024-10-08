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

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import se.oidc.oidfed.base.configuration.MetadataParameter;
import se.oidc.oidfed.base.configuration.ValueType;
import se.oidc.oidfed.base.process.metadata.PolicyMergeException;
import se.oidc.oidfed.base.process.metadata.PolicyOperatorFactory;
import se.oidc.oidfed.base.process.metadata.PolicyProcessingException;
import se.oidc.oidfed.base.process.metadata.PolicyTranslationException;
import se.oidc.oidfed.base.process.metadata.impl.DefaultPolicyOperatorFactory;
import se.oidc.oidfed.base.process.metadata.policyoperators.PolicyOperator;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Metadata policy parameter
 */
@Data
@NoArgsConstructor
@Slf4j
public class MetadataParameterPolicy {

  public MetadataParameterPolicy(final MetadataParameter parameter, final Map<String, PolicyOperator> policyOperators) {
    this.parameter = parameter;
    this.policyOperators = policyOperators;
  }

  protected MetadataParameter parameter;
  protected Map<String, PolicyOperator> policyOperators = new HashMap<>();

  public MetadataParameterPolicy mergeWithSubordinate(final MetadataParameterPolicy subordinateMetadataParameterPolicy)
      throws PolicyMergeException, PolicyTranslationException, PolicyProcessingException {
    if (subordinateMetadataParameterPolicy == null) {
      log.debug("Subordinate policy for metadata parameter {} is null. Skipping merge", this.parameter.getName());
      return this;
    }
    final MetadataParameterPolicyBuilder builder = MetadataParameterPolicy.builder(this.parameter);
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

  public static MetadataParameterPolicyBuilder builder(final MetadataParameter parameter)
      throws PolicyTranslationException {
    if (parameter.getValueType().equals(ValueType.OBJECT)) {
      throw new PolicyTranslationException(
          "Metadata policy is not allowed for metadata parameters holding JSON objects");
    }
    return new MetadataParameterPolicyBuilder(parameter);
  }

  public static MetadataParameterPolicyBuilder builder(final MetadataParameter parameter,
      final PolicyOperatorFactory policyOperatorFactory) {
    return new MetadataParameterPolicyBuilder(parameter, policyOperatorFactory);
  }

  public static class MetadataParameterPolicyBuilder {

    protected MetadataParameterPolicy metadataParameterPolicy;
    protected PolicyOperatorFactory policyOperatorFactory;

    public MetadataParameterPolicyBuilder(final MetadataParameter parameter) {
      this(parameter, new DefaultPolicyOperatorFactory());
    }

    public MetadataParameterPolicyBuilder(final MetadataParameter parameter,
        final PolicyOperatorFactory policyOperatorFactory) {
      this.metadataParameterPolicy = new MetadataParameterPolicy();
      this.metadataParameterPolicy.setParameter(parameter);
      this.policyOperatorFactory = policyOperatorFactory;
    }

    public MetadataParameterPolicyBuilder add(final PolicyOperator policyOperator) {
      this.metadataParameterPolicy.getPolicyOperators().put(policyOperator.getName(), policyOperator);
      return this;
    }

    public MetadataParameterPolicyBuilder add(final String operatorName, final Object value)
        throws PolicyTranslationException, PolicyProcessingException {
      final PolicyOperator policyOperator = this.policyOperatorFactory.getPolicyOperator(
          operatorName, this.metadataParameterPolicy.getParameter().getValueType(), value);
      this.metadataParameterPolicy.getPolicyOperators().put(operatorName, policyOperator);
      return this;
    }

    public MetadataParameterPolicyBuilder skipSubordinates(final boolean skipSubordinates) {
      throw new IllegalArgumentException("Skip subordinates is not supported");
    }

    public MetadataParameterPolicy build() {
      return this.metadataParameterPolicy;
    }
  }

}
