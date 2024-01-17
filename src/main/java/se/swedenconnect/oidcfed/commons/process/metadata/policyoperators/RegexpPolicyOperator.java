package se.swedenconnect.oidcfed.commons.process.metadata.policyoperators;

import java.util.List;

import se.swedenconnect.oidcfed.commons.configuration.ValueType;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyMergeException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyProcessingException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyTranslationException;
import se.swedenconnect.oidcfed.commons.utils.OidcUtils;

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
