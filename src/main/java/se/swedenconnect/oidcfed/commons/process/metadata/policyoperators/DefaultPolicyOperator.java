package se.swedenconnect.oidcfed.commons.process.metadata.policyoperators;

import java.util.List;

import org.springframework.lang.NonNull;

import se.swedenconnect.oidcfed.commons.process.metadata.PolicyMergeException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyProcessingException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyTranslationException;
import se.swedenconnect.oidcfed.commons.utils.OidcUtils;

/**
 * Implementation of the "default" policy operator
 */
public class DefaultPolicyOperator extends AbstractPolicyOperator<Object> {

  public static final String OPERATOR_NAME = "default";

  public DefaultPolicyOperator(Object value, String valueType)
    throws PolicyTranslationException, PolicyProcessingException {
    super(value, valueType);
  }

  @Override protected String getPolicyValueType() {
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

  @Override public PolicyOperator mergeWithSubordinate(PolicyOperator policyOperator) throws PolicyMergeException {
    checkPolicyOperatorClass(policyOperator, this.getClass());
    checkEquality(policyOperator);
    return this;
  }

  @Override public List<String> getModifiedMetadataValues(@NonNull List<String> metadataParameterValue) {
    return metadataParameterValue.isEmpty()
      ? getNormalizedOperatorValue()
      : metadataParameterValue;
  }

  @Override public boolean isMetadataValid(@NonNull List<String> metadataParameterValue) {
    return !metadataParameterValue.isEmpty();
  }
}
