package se.swedenconnect.oidcfed.commons.process.metadata.policyoperators;

import java.util.HashSet;
import java.util.List;

import se.swedenconnect.oidcfed.commons.process.metadata.PolicyMergeException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyProcessingException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyTranslationException;
import se.swedenconnect.oidcfed.commons.utils.OidcUtils;

/**
 * Implementation of the "subset_of" policy operator
 */
public class SubsetOfPolicyOperator extends AbstractPolicyOperator<Object> {

  public static final String OPERATOR_NAME = "subset_of";

  public SubsetOfPolicyOperator(Object value, String valueType)
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
    List<String> intersection = getIntersection(policyOperator.getNormalizedOperatorValue());
    return new SubsetOfPolicyOperator(OidcUtils.convertToValueObject(intersection, valueType), valueType);
  }

  @Override public List<String> getModifiedMetadataValues(List<String> metadataParameterValue) {
    return getIntersection(metadataParameterValue);
  }

  @Override public boolean isMetadataValid(List<String> metadataParameterValue) {
    return new HashSet<>(getNormalizedOperatorValue()).containsAll(metadataParameterValue);
  }
}
