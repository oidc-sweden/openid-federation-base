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
import se.oidc.oidfed.base.process.metadata.PolicyMergeException;
import se.oidc.oidfed.base.process.metadata.PolicyProcessingException;
import se.oidc.oidfed.base.process.metadata.PolicyTranslationException;
import se.oidc.oidfed.base.utils.OidcUtils;

/**
 * Implementation of the "regexp" policy operator.
 */
public class RegexpPolicyOperator extends AbstractPolicyOperator<Object> {

  public static final String OPERATOR_NAME = "regexp";

  public RegexpPolicyOperator(Object value, String valueType)
    throws PolicyTranslationException, PolicyProcessingException {
    super(value, valueType);
    if (!valueType.equals(ValueType.STRING_ARRAY) && !valueType.equals(ValueType.STRING)) {
      throw new PolicyProcessingException("Regexp operator can only be applied to string metadata values");
    }
  }

  @Override protected String getPolicyValueType() throws PolicyProcessingException {
    if (value == null) {
      return ValueType.STRING_ARRAY;
    }
    return (value instanceof List<?>)
      ? ValueType.STRING_ARRAY
      : ValueType.STRING;
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

  @Override public PolicyOperator mergeWithSubordinate(PolicyOperator policyOperator)
    throws PolicyMergeException, PolicyTranslationException, PolicyProcessingException {
    checkPolicyOperatorClass(policyOperator, this.getClass());
    List<String> union = getUnion(policyOperator.getNormalizedOperatorValue());
    // The merged output will always be a list
    String outPutValueType = getArrayPolicyValueTypeFromValueTYpe();
    return new AddPolicyOperator(OidcUtils.convertToValueObject(union, outPutValueType), outPutValueType);
  }

  @Override public List<String> getModifiedMetadataValues(List<String> metadataParameterValue) {
    // This is not a modifier. Returning the metadata unaltered.
    return metadataParameterValue;
  }

  @Override public boolean isMetadataValid(List<String> metadataParameterValue) {
    return getNormalizedOperatorValue().stream()
      .allMatch(regexp ->
        metadataParameterValue.stream()
          .allMatch(s -> s.matches(regexp))
      );
  }
}
