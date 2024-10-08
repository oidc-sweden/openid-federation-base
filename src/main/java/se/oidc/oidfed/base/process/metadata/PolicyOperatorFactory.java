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
package se.oidc.oidfed.base.process.metadata;

import se.oidc.oidfed.base.process.metadata.policyoperators.PolicyOperator;

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
