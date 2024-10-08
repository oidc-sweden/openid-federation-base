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
package se.oidc.oidfed.base.process.chain;

import se.oidc.oidfed.base.data.federation.EntityStatement;

import java.util.List;

/**
 * Chain validator interface used to validate federation data through chain validation
 */
public interface FederationChainValidator {

  /**
   * Validates a chain from Trust Anchor to target entity and process metadata through the policies of the chain.
   *
   * <p>
   * This function does not validate the Trust Marks of the leaf statement. Trust Mark validation is a separate process
   * that in itself will use this function for chain validation of Trust Mark Issuers.
   * </p>
   *
   * <p>
   * In the standard, a chain starts with the target Entity and ends with the Trust Anchor. However, the validation
   * process is processing the chain from Trust Anchor to target entity in order to validate the superior entity key
   * before it is used to validate the data of the subordinate. This is the natural processing order. Paths can be
   * provided in any order as the first step of the validation process is to arrange the path Entity Statements in the
   * correct order.
   * </p>
   *
   * @param chain the trust chain starting from the Trust Anchor Entity Configuration and ending with the target
   *     Entity Configuration
   * @return chain validation result
   * @throws ChainValidationException errors validating the chain
   */
  ChainValidationResult validate(final List<EntityStatement> chain) throws ChainValidationException;

}
