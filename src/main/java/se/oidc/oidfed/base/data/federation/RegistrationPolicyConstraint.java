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
package se.oidc.oidfed.base.data.federation;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * A single registration policy constraint rule, as defined by Section 3 of OpenID Federation Registration Policy 1.0.
 * <p>
 * A rule is satisfied by a Subordinate Statement when at least one of the registration policies of {@link #policy}
 * appears in the {@code registration_policy} claim of that statement. A rule only applies to a Subordinate Statement
 * whose subject has one of the Entity Types of {@link #entityTypes}, and applies to every Entity Type when
 * {@code entityTypes} is absent.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RegistrationPolicyConstraint {

  /**
   * Registration policy identifiers, of which at least one must be declared by a Subordinate Statement for this rule
   * to be satisfied. Required, and must not be empty.
   */
  @JsonProperty("policy")
  private List<String> policy;

  /**
   * The Entity Types this rule applies to. Optional, and must not be empty when present. A rule without Entity Types
   * applies to every Entity Type.
   */
  @JsonProperty("entity_types")
  private List<String> entityTypes;

}
