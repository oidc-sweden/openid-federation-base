/*
 * Copyright 2024 OIDC Sweden
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.oidc.oidfed.base.process.metadata.impl;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import se.oidc.oidfed.base.process.metadata.PolicyTranslationException;
import se.oidc.oidfed.base.process.metadata.policyoperators.EssentialPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.IntersectsPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.OneOfPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.RegexpPolicyOperator;
import se.oidc.oidfed.base.process.metadata.PolicyOperatorFactory;
import se.oidc.oidfed.base.process.metadata.PolicyProcessingException;
import se.oidc.oidfed.base.process.metadata.policyoperators.AddPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.DefaultPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.SkipSubordinatesPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.PolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.SubsetOfPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.SupersetOfPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.ValuePolicyOperator;

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

    return switch (policyOperatorName) {
      case ValuePolicyOperator.OPERATOR_NAME -> new ValuePolicyOperator(value, valueType);
      case AddPolicyOperator.OPERATOR_NAME -> new AddPolicyOperator(value, valueType);
      case DefaultPolicyOperator.OPERATOR_NAME -> new DefaultPolicyOperator(value, valueType);
      case EssentialPolicyOperator.OPERATOR_NAME -> {
        if (!(value instanceof Boolean)) {
          throw new PolicyProcessingException("Illegal value type");
        }
        yield new EssentialPolicyOperator((Boolean) value);
      }
      case OneOfPolicyOperator.OPERATOR_NAME -> new OneOfPolicyOperator(value, valueType);
      case SubsetOfPolicyOperator.OPERATOR_NAME -> new SubsetOfPolicyOperator(value, valueType);
      case SupersetOfPolicyOperator.OPERATOR_NAME -> new SupersetOfPolicyOperator(value, valueType);
      case IntersectsPolicyOperator.OPERATOR_NAME -> new IntersectsPolicyOperator(value, valueType);
      case RegexpPolicyOperator.OPERATOR_NAME -> new RegexpPolicyOperator(value, valueType);
      case SkipSubordinatesPolicyOperator.OPERATOR_NAME -> {
        log.debug("Skip subordinates not supported, skipping");
        yield null;
      }
      default -> {
        log.debug("Unrecognized policy operator: {}", policyOperatorName);
        yield null;
        // This is not necessarily an error if the policy operator is non-critical.
        // The Caller gets to decide how to handle this.
      }
    };
  }
}
