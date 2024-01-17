package se.swedenconnect.oidcfed.commons.process.metadata;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;

import se.swedenconnect.oidcfed.commons.data.metadata.policy.EntityTypeMetadataPolicy;

/**
 * Interface for metadata policy serializer. This is provided as an Interface to allow different experimental
 * serialization formats
 */
public interface MetadataPolicySerializer {

  /**
   * Convert {@link EntityTypeMetadataPolicy} to JSON object Map.
   *
   * @param entityTypeMetadataPolicy metadata policy for federation entity
   * @return JSON object Map
   */
  Map<String, Object> toJsonObject(EntityTypeMetadataPolicy entityTypeMetadataPolicy);

  /**
   * Convert JSON object Map to {@link EntityTypeMetadataPolicy}
   *
   * @param jsonObject federation entity metadata JSON object Map
   * @param criticalOperators list of policy operators that MUST be supported
   * @return {@link EntityTypeMetadataPolicy}
   * @throws PolicyProcessingException error processing policy data
   */
  EntityTypeMetadataPolicy fromJsonObject(Map<String, Object> jsonObject, List<String> criticalOperators)
    throws PolicyProcessingException, PolicyTranslationException;

}
