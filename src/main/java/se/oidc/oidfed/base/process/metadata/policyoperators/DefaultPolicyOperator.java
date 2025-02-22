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

import jakarta.annotation.Nonnull;
import se.oidc.oidfed.base.process.metadata.PolicyTranslationException;
import se.oidc.oidfed.base.process.metadata.PolicyMergeException;
import se.oidc.oidfed.base.process.metadata.PolicyProcessingException;
import se.oidc.oidfed.base.utils.OidcUtils;

/**
 * Implementation of the "default" policy operator
 */
public class DefaultPolicyOperator extends AbstractPolicyOperator<Object> {

  public static final String OPERATOR_NAME = "default";

  public DefaultPolicyOperator(Object value, String valueType)
    throws PolicyTranslationException, PolicyProcessingException {
    super(value, valueType);
  }

  @Override protected String getPolicyValueType() {
    return valueType;
  }

  @Override protected boolean isEmptyValueAllowed() {
    return false;
  }

  @Override protected List<String> deriveNormalizedValue() throws PolicyTranslationException {
    return OidcUtils.convertToStringList(this.value, this.policyValueType);
  }

  @Override public String getName() {
    return OPERATOR_NAME;
  }

  @Override public PolicyOperator mergeWithSubordinate(PolicyOperator policyOperator) throws PolicyMergeException {
    checkPolicyOperatorClass(policyOperator, this.getClass());
    checkEquality(policyOperator);
    return this;
  }

  @Override public List<String> getModifiedMetadataValues(@Nonnull List<String> metadataParameterValue) {
    return metadataParameterValue.isEmpty()
      ? getNormalizedOperatorValue()
      : metadataParameterValue;
  }

  @Override public boolean isMetadataValid(@Nonnull List<String> metadataParameterValue) {
    return !metadataParameterValue.isEmpty();
  }
}
