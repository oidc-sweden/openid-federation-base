package se.swedenconnect.oidcfed.commons.process.metadata;

import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.PolicyOperator;

/**
 * Interface for creating an instance of {@link PolicyOperator}
 */
public interface PolicyOperatorFactory {

  /**
   * Creates an instance of {@link PolicyOperator}
   *
   * @param policyOperatorName the name of the policy operator
   * @param valueType the value type for metadata parameter values
   * @param value the value of the policy operator
   * @return {@link PolicyOperator} object if policy operator is recognized, otherwise null
   * @throws PolicyTranslationException error converting between policy value and normalized value
   * @throws PolicyProcessingException error processing policy data
   */
  PolicyOperator getPolicyOperator(String policyOperatorName, String valueType, Object value)
    throws PolicyTranslationException, PolicyProcessingException;

}
