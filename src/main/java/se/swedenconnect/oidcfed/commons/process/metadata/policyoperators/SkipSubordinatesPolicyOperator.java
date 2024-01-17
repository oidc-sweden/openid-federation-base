package se.swedenconnect.oidcfed.commons.process.metadata.policyoperators;

import java.util.List;

import se.swedenconnect.oidcfed.commons.configuration.ValueType;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyMergeException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyProcessingException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyTranslationException;

/**
 * Implementation of the "enforced" policy operator
 */
public class SkipSubordinatesPolicyOperator extends AbstractPolicyOperator<Boolean> {

  public static final String OPERATOR_NAME = "skip_subordinates";

  public SkipSubordinatesPolicyOperator(Boolean value) throws PolicyTranslationException, PolicyProcessingException {
    super(value, ValueType.BOOLEAN);
  }

  @Override protected String getPolicyValueType() throws PolicyProcessingException {
    return valueType;
  }

  @Override protected boolean isEmptyValueAllowed() {
    return false;
  }

  @Override protected List<String> deriveNormalizedValue() throws PolicyTranslationException {
    return List.of(String.valueOf(this.value));
  }

  @Override public String getName() {
    return OPERATOR_NAME;
  }

  @Override public PolicyOperator mergeWithSubordinate(PolicyOperator policyOperator)
    throws PolicyMergeException, PolicyTranslationException, PolicyProcessingException {
    checkPolicyOperatorClass(policyOperator, this.getClass());
    // if enforced is set in this policy, then keep this, else use new operator.
    return this.value
      ? this
      : policyOperator;
  }

  @Override public List<String> getModifiedMetadataValues(List<String> metadataParameterValue) {
    return metadataParameterValue;
  }

  @Override public boolean isMetadataValid(List<String> metadataParameterValue) {
    return true;
  }
}
