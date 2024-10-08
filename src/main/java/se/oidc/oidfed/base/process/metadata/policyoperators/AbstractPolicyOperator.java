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

import lombok.Getter;
import lombok.Setter;
import se.oidc.oidfed.base.configuration.ValueType;
import se.oidc.oidfed.base.process.metadata.PolicyTranslationException;
import se.oidc.oidfed.base.process.metadata.PolicyMergeException;
import se.oidc.oidfed.base.process.metadata.PolicyProcessingException;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;

/**
 * Abstract implementation of policy operator
 */
public abstract class AbstractPolicyOperator<T> implements PolicyOperator {

  @Getter
  protected String valueType;

  protected String policyValueType;

  @Setter
  T value;
  protected List<String> normalizedValue;

  public AbstractPolicyOperator(final T value, final String valueType) throws PolicyTranslationException,
      PolicyProcessingException {
    this.value = value;
    this.valueType = valueType;
    this.policyValueType = this.getPolicyValueType();
    this.normalizedValue = Optional.ofNullable(this.deriveNormalizedValue()).orElse(List.of());
    this.validate(this.isEmptyValueAllowed(), this.policyValueType);
  }

  protected abstract String getPolicyValueType() throws PolicyProcessingException;

  protected abstract boolean isEmptyValueAllowed();

  protected abstract List<String> deriveNormalizedValue() throws PolicyTranslationException;

  @Override
  public boolean isSupported(final List<String> supportedPolicyOperators) {
    return supportedPolicyOperators.contains(this.getName());
  }

  @Override
  public T getPolicyOperatorValue() {
    return this.value;
  }

  @Override
  public List<String> getNormalizedOperatorValue() {
    return this.normalizedValue;
  }

  protected void validate(final boolean emptyValueAllowed, final String policyValueType)
      throws PolicyProcessingException {
    final List<String> normalizedOperatorValue = this.getNormalizedOperatorValue();
    if (!emptyValueAllowed) {
      if (normalizedOperatorValue.isEmpty()) {
        throw new PolicyProcessingException("Value is empty while required to have content");
      }
    }

    if (policyValueType.equals(ValueType.INTEGER) ||
        policyValueType.equals(ValueType.STRING) ||
        policyValueType.equals(ValueType.BOOLEAN) ||
        policyValueType.equals(ValueType.SPACE_SEPARATED_STRINGS)) {
      if (normalizedOperatorValue.size() > 1) {
        throw new PolicyProcessingException(
            "Single value was expected but value contains " + normalizedOperatorValue.size() + " objects");
      }
    }

    switch (policyValueType) {
    case ValueType.INTEGER:
      if (!(this.value instanceof Integer)) {
        throw new PolicyProcessingException("Value is not of declared value type");
      }
      break;
    case ValueType.STRING:
    case ValueType.SPACE_SEPARATED_STRINGS:
      if (!(this.value instanceof String)) {
        throw new PolicyProcessingException("Value is not of declared value type");
      }
      break;
    case ValueType.BOOLEAN:
      if (!(this.value instanceof Boolean)) {
        throw new PolicyProcessingException("Value is not of declared value type");
      }
      break;
    case ValueType.BOOLEAN_ARRAY:
      if (!(this.value instanceof final List<?> booleanValueList)) {
        throw new PolicyProcessingException("Value is not of declared value type");
      }
      if (booleanValueList.stream().anyMatch(o -> !(o instanceof Boolean))) {
        throw new PolicyProcessingException("Value is not of declared value type");
      }
      break;
    case ValueType.STRING_ARRAY:
      if (!(this.value instanceof final List<?> strValueList)) {
        throw new PolicyProcessingException("Value is not of declared value type");
      }
      if (strValueList.stream().anyMatch(o -> !(o instanceof String))) {
        throw new PolicyProcessingException("Value is not of declared value type");
      }
      break;
    case ValueType.INTEGER_ARRAY:
      if (!(this.value instanceof final List<?> intValueList)) {
        throw new PolicyProcessingException("Value is not of declared value type");
      }
      if (intValueList.stream().anyMatch(o -> !(o instanceof Integer))) {
        throw new PolicyProcessingException("Value is not of declared value type");
      }
      break;
    default:
      throw new PolicyProcessingException("Illegal value type: " + this.valueType);
    }
  }

  protected void checkPolicyOperatorClass(final PolicyOperator policyOperator,
      final Class<? extends PolicyOperator> operatorClass)
      throws PolicyMergeException {
    try {
      if (!policyOperator.getClass().equals(operatorClass)) {
        throw new PolicyTranslationException("Incompatible policy operator types");
      }
    }
    catch (final PolicyTranslationException e) {
      throw new PolicyMergeException(e.getMessage());
    }
  }

  protected List<String> getUnion(final List<String> otherValues) {
    final List<String> thisValue = this.getNormalizedOperatorValue();
    final List<String> union = new ArrayList<>(otherValues);
    thisValue.stream()
        .filter(s -> !union.contains(s))
        .forEach(union::add);
    return union;
  }

  protected List<String> getIntersection(final List<String> otherValues) {
    final List<String> thisValue = this.getNormalizedOperatorValue();
    final List<String> intersection = new ArrayList<>(otherValues);
    otherValues.stream()
        .filter(s -> !thisValue.contains(s))
        .forEach(intersection::remove);
    return intersection;
  }

  protected void checkEquality(final PolicyOperator superiorPolicy) throws PolicyMergeException {
    final List<String> superiorValue = superiorPolicy.getNormalizedOperatorValue();
    final List<String> thisValue = this.getNormalizedOperatorValue();
    if (superiorValue.size() != thisValue.size()) {
      throw new PolicyMergeException("Merge error. Policies have different number of values");
    }
    if (!new HashSet<>(superiorValue).containsAll(thisValue)) {
      throw new PolicyMergeException("Merge error. Policies have different values");
    }
  }

  protected String getArrayPolicyValueTypeFromValueTYpe() {
    return switch (this.valueType) {
      case ValueType.INTEGER -> ValueType.INTEGER_ARRAY;
      case ValueType.STRING, ValueType.SPACE_SEPARATED_STRINGS -> ValueType.STRING_ARRAY;
      case ValueType.BOOLEAN -> ValueType.BOOLEAN_ARRAY;
      default -> this.valueType;
    };
  }

}
