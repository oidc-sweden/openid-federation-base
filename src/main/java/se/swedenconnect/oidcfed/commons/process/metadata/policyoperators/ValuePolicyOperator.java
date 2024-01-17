package se.swedenconnect.oidcfed.commons.process.metadata.policyoperators;

import java.util.List;

import se.swedenconnect.oidcfed.commons.process.metadata.PolicyMergeException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyProcessingException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyTranslationException;
import se.swedenconnect.oidcfed.commons.utils.OidcUtils;

/**
 * Implementation of the "value" policy operator
 */
public class ValuePolicyOperator extends AbstractPolicyOperator<Object>{

  public static final String OPERATOR_NAME = "value";

  public ValuePolicyOperator(Object value, String valueType)
    throws PolicyProcessingException, PolicyTranslationException {
    super(value, valueType);
  }

  @Override protected String getPolicyValueType() throws PolicyProcessingException {
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

  @Override public PolicyOperator mergeWithSubordinate(PolicyOperator policyOperator)
    throws PolicyMergeException {
    checkPolicyOperatorClass(policyOperator, this.getClass());
    checkEquality(policyOperator);
    return this;
  }

  @Override public List<String> getModifiedMetadataValues(List<String> metadataParameterValue) {
    return this.getNormalizedOperatorValue();
  }

  @Override public boolean isMetadataValid(List<String> metadataParameterValue) {
    return metadataParameterValue != null &&
      metadataParameterValue.size() == 1 &&
      metadataParameterValue.get(0).equals(getNormalizedOperatorValue().get(0));
  }
}
