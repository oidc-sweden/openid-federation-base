package se.swedenconnect.oidcfed.commons.data.metadata.policy;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.oidcfed.commons.data.oidcfed.EntityStatementDefinedParams;
import se.swedenconnect.oidcfed.commons.process.metadata.MetadataPolicySerializer;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyMergeException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyProcessingException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyTranslationException;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.PolicyOperator;
import se.swedenconnect.oidcfed.commons.utils.OidcUtils;

/**
 * Policy parameters for the metadata policy
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Slf4j
public class EntityTypeMetadataPolicy {

  private Map<String, MetadataParameterPolicy> metadataParameterPolicyMap;

  public EntityTypeMetadataPolicy mergeWithSubordinate(EntityTypeMetadataPolicy subordinateEntityTypeMetadataPolicy)
    throws PolicyMergeException, PolicyTranslationException, PolicyProcessingException {
    if (subordinateEntityTypeMetadataPolicy == null) {
      return this;
    }
    EntityTypeMetadataPolicyBuilder builder = EntityTypeMetadataPolicy.builder();
    List<String> allMetadataParameterNames = new ArrayList<>(this.metadataParameterPolicyMap.keySet());
    Map<String, MetadataParameterPolicy> subordinateMetadataParameterPolicyMap = subordinateEntityTypeMetadataPolicy.getMetadataParameterPolicyMap();
    subordinateMetadataParameterPolicyMap.keySet().stream()
      .filter(s -> !allMetadataParameterNames.contains(s))
      .forEach(allMetadataParameterNames::add);

    for (String metadataParameterName : allMetadataParameterNames) {
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

    public EntityTypeMetadataPolicyBuilder addMetadataParameterPolicy(MetadataParameterPolicy metadataParameterPolicy) {
      entityTypeMetadataPolicy.getMetadataParameterPolicyMap()
        .put(metadataParameterPolicy.getParameter().getName(), metadataParameterPolicy);
      return this;
    }

    public EntityTypeMetadataPolicy build() {
      return this.entityTypeMetadataPolicy;
    }

  }

}
