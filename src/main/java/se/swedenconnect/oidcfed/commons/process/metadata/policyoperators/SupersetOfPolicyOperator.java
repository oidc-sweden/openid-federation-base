package se.swedenconnect.oidcfed.commons.process.metadata.policyoperators;

import java.util.HashSet;
import java.util.List;

import se.swedenconnect.oidcfed.commons.process.metadata.PolicyMergeException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyProcessingException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyTranslationException;
import se.swedenconnect.oidcfed.commons.utils.OidcUtils;

/**
 * Implementation of the "superset_of" policy operator
 */
public class SupersetOfPolicyOperator extends AbstractPolicyOperator<Object> {

  public static final String OPERATOR_NAME = "superset_of";

  public SupersetOfPolicyOperator(Object value, String valueType)
    throws PolicyTranslationException, PolicyProcessingException {
    super(value, valueType);
  }

  @Override protected String getPolicyValueType() throws PolicyProcessingException {
    return getArrayPolicyValueTypeFromValueTYpe();
  }

  @Override protected boolean isEmptyValueAllowed() {
    return true;
  }

  @Override protected List<String> deriveNormalizedValue() throws PolicyTranslationException {
    return OidcUtils.convertListToStringList(this.value, this.policyValueType);
  }

  @Override public String getName() {
    return OPERATOR_NAME;
  }

  @Override public PolicyOperator mergeWithSubordinate(PolicyOperator policyOperator)
    throws PolicyMergeException, PolicyTranslationException, PolicyProcessingException {
    checkPolicyOperatorClass(policyOperator, this.getClass());
    List<String> union = getUnion(policyOperator.getNormalizedOperatorValue());
    return new SupersetOfPolicyOperator(OidcUtils.convertToValueObject(union, this.valueType), this.valueType);
  }

  @Override public List<String> getModifiedMetadataValues(List<String> metadataParameterValue) {
    // This is not a modifier. Returning the metadata unaltered.
    return metadataParameterValue;
  }

  @Override public boolean isMetadataValid(List<String> metadataParameterValue) {
    return new HashSet<>(metadataParameterValue).containsAll(getNormalizedOperatorValue());
  }
}
