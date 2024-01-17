package se.swedenconnect.oidcfed.commons.process.metadata.policyoperators;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.oidcfed.commons.configuration.ValueType;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyMergeException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyProcessingException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyTranslationException;

/**
 * Abstract implementation of policy operator
 */
public abstract class AbstractPolicyOperator<T extends Object> implements PolicyOperator {

  @Getter protected String valueType;
  @Getter protected String policyValueType;
  @Setter T value;
  protected List<String> normalizedValue;

  public AbstractPolicyOperator(T value, String valueType) throws PolicyTranslationException,
    PolicyProcessingException {
    this.value = value;
    this.valueType = valueType;
    this.policyValueType = getPolicyValueType();
    this.normalizedValue = Optional.ofNullable(deriveNormalizedValue()).orElse(List.of());
    validate(isEmptyValueAllowed(), policyValueType);
  }

  protected abstract String getPolicyValueType() throws PolicyProcessingException;

  protected abstract boolean isEmptyValueAllowed();

  protected abstract List<String> deriveNormalizedValue() throws PolicyTranslationException;

  @Override public boolean isSupported(List<String> supportedPolicyOperators) {
    return supportedPolicyOperators.contains(getName());
  }

  @Override public T getPolicyOperatorValue() {
    return value;
  }

  @Override public List<String> getNormalizedOperatorValue() {
    return this.normalizedValue;
  }

  protected void validate(boolean emptyValueAllowed, String policyValueType) throws PolicyProcessingException {
    List<String> normalizedOperatorValue = getNormalizedOperatorValue();
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
      if (!(value instanceof Integer)) {
        throw new PolicyProcessingException("Value is not of declared value type");
      }
      break;
    case ValueType.STRING:
    case ValueType.SPACE_SEPARATED_STRINGS:
      if (!(value instanceof String)) {
        throw new PolicyProcessingException("Value is not of declared value type");
      }
      break;
    case ValueType.BOOLEAN:
      if (!(value instanceof Boolean)) {
        throw new PolicyProcessingException("Value is not of declared value type");
      }
      break;
    case ValueType.BOOLEAN_ARRAY:
      if (!(value instanceof List<?>)) {
        throw new PolicyProcessingException("Value is not of declared value type");
      }
      List<?> booleanValueList = (List<?>) value;
      if (booleanValueList.stream().anyMatch(o -> !(o instanceof Boolean))){
        throw new PolicyProcessingException("Value is not of declared value type");
      }
      break;
    case ValueType.STRING_ARRAY:
      if (!(value instanceof List<?>)) {
        throw new PolicyProcessingException("Value is not of declared value type");
      }
      List<?> strValueList = (List<?>) value;
      if (strValueList.stream().anyMatch(o -> !(o instanceof String))){
        throw new PolicyProcessingException("Value is not of declared value type");
      }
      break;
    case ValueType.INTEGER_ARRAY:
      if (!(value instanceof List<?>)) {
        throw new PolicyProcessingException("Value is not of declared value type");
      }
      List<?> intValueList = (List<?>) value;
      if (intValueList.stream().anyMatch(o -> !(o instanceof Integer))){
        throw new PolicyProcessingException("Value is not of declared value type");
      }
      break;
    default:
      throw new PolicyProcessingException("Illegal value type: " + valueType);
    }
  }

  protected void checkPolicyOperatorClass(PolicyOperator policyOperator, Class<? extends PolicyOperator> operatorClass)
    throws PolicyMergeException {
    try {
      if (!policyOperator.getClass().equals(operatorClass)) {
        throw new PolicyTranslationException("Incompatible policy operator types");
      }
    }
    catch (PolicyTranslationException e) {
      throw new PolicyMergeException(e.getMessage());
    }
  }

  protected List<String> getUnion (List<String> otherValues) {
    List<String> thisValue = getNormalizedOperatorValue();
    List<String> union = new ArrayList<>(otherValues);
    thisValue.stream()
      .filter(s -> !union.contains(s))
      .forEach(union::add);
    return union;
  }

  protected List<String> getIntersection (List<String> otherValues) {
    List<String> thisValue = getNormalizedOperatorValue();
    List<String> intersection = new ArrayList<>(otherValues);
    otherValues.stream()
      .filter(s -> !thisValue.contains(s))
      .forEach(intersection::remove);
    return intersection;
  }

  protected void checkEquality(PolicyOperator superiorPolicy) throws PolicyMergeException {
    List<String> superiorValue = superiorPolicy.getNormalizedOperatorValue();
    List<String> thisValue = getNormalizedOperatorValue();
    if (superiorValue.size() != thisValue.size()){
      throw new PolicyMergeException("Merge error. Policies have different number of values");
    }
    if (!new HashSet<>(superiorValue).containsAll(thisValue)){
      throw new PolicyMergeException("Merge error. Policies have different values");
    }
  }

  protected String getArrayPolicyValueTypeFromValueTYpe() throws PolicyProcessingException {
    switch (valueType) {
    case ValueType.INTEGER:
      return ValueType.INTEGER_ARRAY;
    case ValueType.STRING:
    case ValueType.SPACE_SEPARATED_STRINGS:
      return ValueType.STRING_ARRAY;
    case ValueType.BOOLEAN:
      return ValueType.BOOLEAN_ARRAY;
    default:
      return valueType;
    }
  }

}
