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
package se.oidc.oidfed.base.data.federation.builders;

import java.util.HashMap;
import java.util.Map;

import com.nimbusds.jose.jwk.JWKSet;

import se.oidc.oidfed.base.data.federation.TrustMarkOwner;

/**
 * Builder for the trust mark owners claim
 */
public class TrustMarkOwnersBuilder {

  /**
   * Trust mark owner builder
   */
  private final Map<String, TrustMarkOwner> trustMarkOwners;

  /**
   * private constructor for the getInstance() function
   */
  private TrustMarkOwnersBuilder() {
    this.trustMarkOwners = new HashMap<>();
  }

  /**
   * Get an instance of this trust mark owner builder
   *
   * @return {@link TrustMarkOwnersBuilder}
   */
  public static TrustMarkOwnersBuilder getInstance() {
    return new TrustMarkOwnersBuilder();
  }

  /**
   * Add trust mark with owner information
   *
   * @param trustMark trust mark ID
   * @param owner trust mark Owner identifier
   * @param jwkSet JWK set of the trust mark owner
   * @return this builder for cascading input
   */
  public TrustMarkOwnersBuilder trustMark(final String trustMark, final String owner, final JWKSet jwkSet) {
    this.trustMarkOwners.put(trustMark, new TrustMarkOwner(owner, jwkSet));
    return this;
  }

  /**
   * Build trust mark owner data
   *
   * @return trust mark owner data
   */
  public Map<String, TrustMarkOwner> build() {
    return this.trustMarkOwners;
  }

}
