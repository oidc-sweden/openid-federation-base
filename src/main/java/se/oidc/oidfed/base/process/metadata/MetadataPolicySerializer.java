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

import se.oidc.oidfed.base.data.metadata.policy.EntityTypeMetadataPolicy;

import java.util.List;
import java.util.Map;

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
  Map<String, Object> toJsonObject(final EntityTypeMetadataPolicy entityTypeMetadataPolicy);

  /**
   * Convert JSON object Map to {@link EntityTypeMetadataPolicy}
   *
   * @param jsonObject federation entity metadata JSON object Map
   * @param criticalOperators list of policy operators that MUST be supported
   * @return {@link EntityTypeMetadataPolicy}
   * @throws PolicyProcessingException error processing policy data
   */
  EntityTypeMetadataPolicy fromJsonObject(final Map<String, Object> jsonObject, final List<String> criticalOperators)
      throws PolicyProcessingException, PolicyTranslationException;

}
