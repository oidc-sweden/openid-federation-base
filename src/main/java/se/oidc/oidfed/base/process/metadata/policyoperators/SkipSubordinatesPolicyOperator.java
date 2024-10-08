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
package se.oidc.oidfed.base.process.metadata.policyoperators;

import java.util.List;

import se.oidc.oidfed.base.configuration.ValueType;
import se.oidc.oidfed.base.process.metadata.PolicyTranslationException;
import se.oidc.oidfed.base.process.metadata.PolicyMergeException;
import se.oidc.oidfed.base.process.metadata.PolicyProcessingException;

/**
 * Implementation of the "enforced" policy operator
 */
public class SkipSubordinatesPolicyOperator extends AbstractPolicyOperator<Boolean> {

  public static final String OPERATOR_NAME = "skip_subordinates";

  public SkipSubordinatesPolicyOperator(Boolean value) throws PolicyTranslationException, PolicyProcessingException {
    super(value, ValueType.BOOLEAN);
  }

  @Override protected String getPolicyValueType() throws PolicyProcessingException {
    return valueType;
  }

  @Override protected boolean isEmptyValueAllowed() {
    return false;
  }

  @Override protected List<String> deriveNormalizedValue() throws PolicyTranslationException {
    return List.of(String.valueOf(this.value));
  }

  @Override public String getName() {
    return OPERATOR_NAME;
  }

  @Override public PolicyOperator mergeWithSubordinate(PolicyOperator policyOperator)
    throws PolicyMergeException, PolicyTranslationException, PolicyProcessingException {
    checkPolicyOperatorClass(policyOperator, this.getClass());
    // if enforced is set in this policy, then keep this, else use new operator.
    return this.value
      ? this
      : policyOperator;
  }

  @Override public List<String> getModifiedMetadataValues(List<String> metadataParameterValue) {
    return metadataParameterValue;
  }

  @Override public boolean isMetadataValid(List<String> metadataParameterValue) {
    return true;
  }
}
