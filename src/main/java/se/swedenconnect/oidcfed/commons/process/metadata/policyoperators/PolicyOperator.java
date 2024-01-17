package se.swedenconnect.oidcfed.commons.process.metadata.policyoperators;

import java.util.List;

import se.swedenconnect.oidcfed.commons.process.metadata.PolicyMergeException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyProcessingException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyTranslationException;

/**
 * Interface for policy operators
 */
public interface PolicyOperator {

  String getName();

  boolean isSupported(List<String> supportedPolicyOperators);

  List<String> getNormalizedOperatorValue();

  Object getPolicyOperatorValue();

  PolicyOperator mergeWithSubordinate(PolicyOperator policyOperator)
    throws PolicyMergeException, PolicyTranslationException, PolicyProcessingException;

  List<String> getModifiedMetadataValues(List<String> metadataParameterValue);

  boolean isMetadataValid(List<String> metadataParameterValue);

}
