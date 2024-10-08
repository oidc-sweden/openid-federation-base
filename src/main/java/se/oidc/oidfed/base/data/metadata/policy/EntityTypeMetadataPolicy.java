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
package se.oidc.oidfed.base.data.metadata.policy;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import se.oidc.oidfed.base.process.metadata.PolicyMergeException;
import se.oidc.oidfed.base.process.metadata.PolicyProcessingException;
import se.oidc.oidfed.base.process.metadata.PolicyTranslationException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Policy parameters for the metadata policy
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Slf4j
public class EntityTypeMetadataPolicy {

  private Map<String, MetadataParameterPolicy> metadataParameterPolicyMap;

  public EntityTypeMetadataPolicy mergeWithSubordinate(
      final EntityTypeMetadataPolicy subordinateEntityTypeMetadataPolicy)
      throws PolicyMergeException, PolicyTranslationException, PolicyProcessingException {
    if (subordinateEntityTypeMetadataPolicy == null) {
      return this;
    }
    final EntityTypeMetadataPolicyBuilder builder = EntityTypeMetadataPolicy.builder();
    final List<String> allMetadataParameterNames = new ArrayList<>(this.metadataParameterPolicyMap.keySet());
    final Map<String, MetadataParameterPolicy> subordinateMetadataParameterPolicyMap =
        subordinateEntityTypeMetadataPolicy.getMetadataParameterPolicyMap();
    subordinateMetadataParameterPolicyMap.keySet().stream()
        .filter(s -> !allMetadataParameterNames.contains(s))
        .forEach(allMetadataParameterNames::add);

    for (final String metadataParameterName : allMetadataParameterNames) {
      if (!this.metadataParameterPolicyMap.containsKey(metadataParameterName)) {
        // Metadata parameter policy is only present in merged policy. Add this
        builder.addMetadataParameterPolicy(subordinateMetadataParameterPolicyMap.get(metadataParameterName));
        continue;
      }
      if (!subordinateMetadataParameterPolicyMap.containsKey(metadataParameterName)) {
        // Metadata parameter policy is only present in this policy. Add this
        builder.addMetadataParameterPolicy(this.metadataParameterPolicyMap.get(metadataParameterName));
        continue;
      }
      // Metadata parameter policy is present in both policies. Merge them
      builder.addMetadataParameterPolicy(
          this.metadataParameterPolicyMap.get(metadataParameterName)
              .mergeWithSubordinate(subordinateMetadataParameterPolicyMap.get(metadataParameterName)));
    }
    return builder.build();
  }

  public static EntityTypeMetadataPolicyBuilder builder() {
    return new EntityTypeMetadataPolicyBuilder();
  }

  public static class EntityTypeMetadataPolicyBuilder {

    EntityTypeMetadataPolicy entityTypeMetadataPolicy;

    public EntityTypeMetadataPolicyBuilder() {
      this.entityTypeMetadataPolicy = new EntityTypeMetadataPolicy(new HashMap<>());
    }

    public EntityTypeMetadataPolicyBuilder addMetadataParameterPolicy(
        final MetadataParameterPolicy metadataParameterPolicy) {
      this.entityTypeMetadataPolicy.getMetadataParameterPolicyMap()
          .put(metadataParameterPolicy.getParameter().getName(), metadataParameterPolicy);
      return this;
    }

    public EntityTypeMetadataPolicy build() {
      return this.entityTypeMetadataPolicy;
    }

  }

}
