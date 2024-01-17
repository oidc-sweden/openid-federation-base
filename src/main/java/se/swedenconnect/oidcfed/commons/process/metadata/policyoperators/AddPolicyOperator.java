package se.swedenconnect.oidcfed.commons.process.metadata.policyoperators;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import se.swedenconnect.oidcfed.commons.process.metadata.PolicyMergeException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyProcessingException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyTranslationException;
import se.swedenconnect.oidcfed.commons.utils.OidcUtils;

/**
 * Implementation of the "add" policy operator
 */
public class AddPolicyOperator extends AbstractPolicyOperator<Object>{

  public static final String OPERATOR_NAME = "add";

  public AddPolicyOperator(Object value, String valueType)
    throws PolicyTranslationException, PolicyProcessingException {
    super(value, valueType);
  }

  @Override protected String getPolicyValueType() throws PolicyProcessingException {
    if (value == null) {
      return valueType;
    }
    return (value instanceof List<?>)
      ? getArrayPolicyValueTypeFromValueTYpe()
      : valueType;
  }

  @Override protected boolean isEmptyValueAllowed() {
    return true;
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
    List<String> updatedMetadata = new ArrayList<>(metadataParameterValue);
    getNormalizedOperatorValue().stream()
      .filter(s -> !metadataParameterValue.contains(s))
      .forEach(updatedMetadata::add);
    return updatedMetadata;
  }

  @Override public boolean isMetadataValid(List<String> metadataParameterValue) {
    return new HashSet<>(metadataParameterValue).containsAll(getNormalizedOperatorValue());
  }
}
