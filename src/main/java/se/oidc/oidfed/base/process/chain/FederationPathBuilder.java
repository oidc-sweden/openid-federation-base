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
 * Chain path builder for OpenID federation.
 */
public interface FederationPathBuilder {

  /**
   * Builds a path of entity statements in the selected order.
   *
   * <p>
   * Note that the order of a chain described in the OpenID federation standard which starts with the leaf and ends with
   * the Trust Anchor. However a top-down path is more naturally to build and to validate and is the order the path is
   * processed by the validator. If this path is exposed externally, use the buildPath function and specify
   * trustAnchorFirst to false.
   * </p>
   *
   * @param entityIdentifier the identifier of the starting entity.
   * @param trustAnchor the trust anchor entity identifier.
   * @param trustAnchorFirst the value of true places the Trust Anchor first in the chain, otherwise last
   * @return the list of entity statements forming the path from the starting entity to the trust anchor.
   * @throws PathBuildingException If there is an error building the path.
   */

  List<EntityStatement> buildPath(
      final String entityIdentifier, final String trustAnchor, final boolean trustAnchorFirst)
      throws PathBuildingException;
}
