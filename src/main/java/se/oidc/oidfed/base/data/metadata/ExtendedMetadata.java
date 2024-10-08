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
package se.oidc.oidfed.base.data.metadata;

import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.Getter;
import lombok.Setter;
import se.oidc.oidfed.base.data.OidcLangJsonSerializer;
import se.oidc.oidfed.base.utils.OidcUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * This class provides the mechanisms needed to extend any of the defined metadata classes with custom properties.
 *
 * @param <T> base metadata class
 */
public class ExtendedMetadata<T extends AbstractOidcFedMetadata> {

  private ExtendedMetadata() {
  }

  /**
   * Parse metadata JSON object to an Extended Metadata object
   *
   * @param metadataJsonObject JSON object of the complete metadata with extended parameters
   * @param jsonSerializer serializer for the base metadata type
   * @throws JsonProcessingException error processing json data
   */
  public ExtendedMetadata(final Map<String, Object> metadataJsonObject, final OidcLangJsonSerializer<T> jsonSerializer)
      throws JsonProcessingException {
    this.baseMetadata = jsonSerializer.parse(metadataJsonObject);
    this.extendedParameters = OidcUtils.getExtensionProperties(metadataJsonObject, this.baseMetadata);
  }

  /** Base metadata */
  @Getter
  @Setter
  T baseMetadata;

  /** Extended parameters not included in the base metadata object */
  @Getter
  @Setter
  private Map<String, Object> extendedParameters;

  /**
   * Get the value of an extended parameter
   *
   * @param parameterName name of the extended parameter
   * @return extended parameter value or null if no such parameter exists
   */
  public Object getExtendedParameter(final String parameterName) {
    return this.extendedParameters.get(parameterName);
  }

  /**
   * Converts the extended metadata to a JSON object
   *
   * @return JSON object
   * @throws JsonProcessingException error processing JSON data
   */
  public Map<String, Object> toJsonObject() throws JsonProcessingException {
    final Map<String, Object> baseMetadataObject = this.baseMetadata != null
        ? this.baseMetadata.toJsonObject()
        : new HashMap<>();
    return this.extendedParameters == null
        ? baseMetadataObject
        : this.mergeMetadata(baseMetadataObject);
  }

  private Map<String, Object> mergeMetadata(final Map<String, Object> baseMetadataObject) {
    final Map<String, Object> mergedMetadata = new HashMap<>(baseMetadataObject);
    this.extendedParameters.keySet()
        .forEach(s -> mergedMetadata.put(s, this.extendedParameters.get(s)));
    return mergedMetadata;
  }

  /**
   * Builder class for the specified base metadata type
   *
   * @param valueClass class of base metadata
   * @param <V> base metadata class
   * @return extended metadata builder
   */
  public static <V extends AbstractOidcFedMetadata> ExtendedMetadataBuilder<V> builder(final Class<V> valueClass) {
    return new ExtendedMetadataBuilder<>();
  }

  /**
   * Builder for extended metadata
   *
   * @param <T> base metadata type
   */
  public static class ExtendedMetadataBuilder<T extends AbstractOidcFedMetadata> {

    /** Extended metadata being built */
    ExtendedMetadata<T> extendedMetadata;

    /**
     * Constructor
     */
    public ExtendedMetadataBuilder() {
      this.extendedMetadata = new ExtendedMetadata<>();
    }

    /**
     * Set base metadata
     *
     * @param baseMetadata base metadata
     * @return this builder
     */
    public ExtendedMetadataBuilder<T> baseMetadata(final T baseMetadata) {
      this.extendedMetadata.baseMetadata = baseMetadata;
      return this;
    }

    /**
     * Add extended parameter
     *
     * @param parameterName parameter name
     * @param value parameter value
     * @return this builder
     */
    public ExtendedMetadataBuilder<T> addParameter(final String parameterName, final String value) {
      final Map<String, Object> extendedParameters = Optional.ofNullable(this.extendedMetadata.getExtendedParameters())
          .orElse(new HashMap<>());
      extendedParameters.put(parameterName, value);
      this.extendedMetadata.extendedParameters = extendedParameters;
      return this;
    }

    /**
     * Build the extended metadata object
     *
     * @return extended metadata
     */
    public ExtendedMetadata<T> build() {
      return this.extendedMetadata;
    }
  }

}
