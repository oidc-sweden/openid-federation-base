package se.swedenconnect.oidcfed.commons.process.metadata.policyoperators;

import java.util.List;

import org.springframework.lang.NonNull;

import se.swedenconnect.oidcfed.commons.configuration.ValueType;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyMergeException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyProcessingException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyTranslationException;
import se.swedenconnect.oidcfed.commons.utils.OidcUtils;

/**
 * Implementation of the "essential" policy operator
 */
public class EssentialPolicyOperator extends AbstractPolicyOperator<Boolean> {

  public static final String OPERATOR_NAME = "essential";

  public EssentialPolicyOperator(@NonNull Boolean value)
    throws PolicyTranslationException, PolicyProcessingException {
    super(value, ValueType.BOOLEAN);
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

  @Override public PolicyOperator mergeWithSubordinate(PolicyOperator policyOperator)
    throws PolicyMergeException, PolicyTranslationException, PolicyProcessingException {
    checkPolicyOperatorClass(policyOperator, this.getClass());
    return new EssentialPolicyOperator(((EssentialPolicyOperator) policyOperator).getPolicyOperatorValue() || value);
  }

  @Override public List<String> getModifiedMetadataValues(List<String> metadataParameterValue) {
    // This is not a modifier. Returning the metadata unaltered.
    return metadataParameterValue;
  }

  @Override public boolean isMetadataValid(List<String> metadataParameterValue) {
    return !getPolicyOperatorValue() || !metadataParameterValue.isEmpty();
  }
}
