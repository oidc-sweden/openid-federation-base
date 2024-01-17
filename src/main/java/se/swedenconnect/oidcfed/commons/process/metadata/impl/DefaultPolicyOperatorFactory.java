package se.swedenconnect.oidcfed.commons.process.metadata.impl;

import java.util.List;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyOperatorFactory;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyProcessingException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyTranslationException;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.AddPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.DefaultPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.SkipSubordinatesPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.EssentialPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.IntersectsPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.OneOfPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.PolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.RegexpPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.SubsetOfPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.SupersetOfPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.ValuePolicyOperator;

/**
 * Default implementation of the {@link PolicyOperatorFactory} interface.
 */
@Slf4j
@NoArgsConstructor
public class DefaultPolicyOperatorFactory implements PolicyOperatorFactory {

  public static DefaultPolicyOperatorFactory getInstance() {
    return new DefaultPolicyOperatorFactory();
  }

  @Override public PolicyOperator getPolicyOperator(String policyOperatorName, String valueType, Object value)
    throws PolicyTranslationException, PolicyProcessingException {

    switch (policyOperatorName) {
    case ValuePolicyOperator.OPERATOR_NAME:
      return new ValuePolicyOperator(value, valueType);
    case AddPolicyOperator.OPERATOR_NAME:
      return new AddPolicyOperator(value, valueType);
    case DefaultPolicyOperator.OPERATOR_NAME:
      return new DefaultPolicyOperator(value, valueType);
    case EssentialPolicyOperator.OPERATOR_NAME:
      if (!(value instanceof Boolean)) {
        throw new PolicyProcessingException("Illegal value type");
      }
      return new EssentialPolicyOperator((Boolean) value);
    case OneOfPolicyOperator.OPERATOR_NAME:
      return new OneOfPolicyOperator(value, valueType);
    case SubsetOfPolicyOperator.OPERATOR_NAME:
      return new SubsetOfPolicyOperator(value, valueType);
    case SupersetOfPolicyOperator.OPERATOR_NAME:
      return new SupersetOfPolicyOperator(value, valueType);
    case IntersectsPolicyOperator.OPERATOR_NAME:
      return new IntersectsPolicyOperator(value, valueType);
    case RegexpPolicyOperator.OPERATOR_NAME:
      return new RegexpPolicyOperator(value, valueType);
    case SkipSubordinatesPolicyOperator.OPERATOR_NAME:
      if (!(value instanceof Boolean)) {
        throw new PolicyProcessingException("Illegal value type");
      }
      return new SkipSubordinatesPolicyOperator((Boolean) value);
    default:
      // This is not necessarily an error if the policy operator is non-critical.
      // The Caller gets to decide how to handle this.
      log.debug("Unrecognized policy operator: {}", policyOperatorName);
      return null;
    }
  }
}
