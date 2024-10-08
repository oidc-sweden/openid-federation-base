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
import java.util.List;
import java.util.Map;

/**
 * Builder for trust mark issuers claim
 */
public class TrustMarkIssuersBuilder {

  Map<String, List<String>> trustMarkIssuers;

  /**
   * Private constructor for the get instance method
   */
  private TrustMarkIssuersBuilder() {
    this.trustMarkIssuers = new HashMap<>();
  }

  /**
   * Get an instance of the trust mark issuers builder
   *
   * @return {@link TrustMarkIssuersBuilder}
   */
  public static TrustMarkIssuersBuilder getInstance() {
    return new TrustMarkIssuersBuilder();
  }

  /**
   * Add trust mark and authorized issuers of this trust mark
   *
   * @param trustMarkId id of the trust mark
   * @param issuers list of authorized issuers entity ID
   * @return this builder for cascading input
   */
  public TrustMarkIssuersBuilder trustMark(final String trustMarkId, final List<String> issuers) {
    this.trustMarkIssuers.put(trustMarkId, issuers);
    return this;
  }

  /**
   * Build the resulting trust mark issuers data
   *
   * @return trust mark issuers data
   */
  public Map<String, List<String>> build() {
    return this.trustMarkIssuers;
  }

}
