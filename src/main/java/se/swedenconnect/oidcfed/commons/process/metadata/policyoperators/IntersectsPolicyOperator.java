package se.swedenconnect.oidcfed.commons.process.metadata.policyoperators;

import java.util.List;

import se.swedenconnect.oidcfed.commons.process.metadata.PolicyMergeException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyProcessingException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyTranslationException;
import se.swedenconnect.oidcfed.commons.utils.OidcUtils;

/**
 * Implementation of the "intersects" policy operator
 */
public class IntersectsPolicyOperator extends AbstractPolicyOperator<Object> {

  public static final String OPERATOR_NAME = "intersects";

  public IntersectsPolicyOperator(Object value, String valueType)
    throws PolicyTranslationException, PolicyProcessingException {
    super(value, valueType);
  }

  @Override protected String getPolicyValueType() throws PolicyProcessingException {
    return getArrayPolicyValueTypeFromValueTYpe();
  }

  @Override protected boolean isEmptyValueAllowed() {
    return false;
  }

  @Override protected List<String> deriveNormalizedValue() throws PolicyTranslationException {
    return OidcUtils.convertListToStringList(this.value, this.policyValueType);
  }

  @Override public String getName() {
    return "intersects";
  }

  @Override public PolicyOperator mergeWithSubordinate(PolicyOperator policyOperator)
    throws PolicyMergeException, PolicyTranslationException, PolicyProcessingException {
    checkPolicyOperatorClass(policyOperator, this.getClass());
    List<String> intersection = getIntersection(policyOperator.getNormalizedOperatorValue());
    return new IntersectsPolicyOperator(OidcUtils.convertToValueObject(intersection, valueType), valueType);
  }

  @Override public List<String> getModifiedMetadataValues(List<String> metadataParameterValue) {
    // This is not a modifier. Returning the metadata unaltered.
    return metadataParameterValue;
  }

  @Override public boolean isMetadataValid(List<String> metadataParameterValue) {
    return getNormalizedOperatorValue().stream()
      .anyMatch(metadataParameterValue::contains);
  }
}
