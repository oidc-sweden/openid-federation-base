package se.swedenconnect.oidcfed.commons.data.metadata;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import com.fasterxml.jackson.core.JsonProcessingException;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.oidcfed.commons.data.OidcLangJsonSerializer;
import se.swedenconnect.oidcfed.commons.utils.OidcUtils;

/**
 * This class provides the mechanisms needed to extend any of the defined metadata classes
 * with custom properties.
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
  public ExtendedMetadata(Map<String, Object> metadataJsonObject, OidcLangJsonSerializer<T> jsonSerializer)
    throws JsonProcessingException {
    this.baseMetadata = jsonSerializer.parse(metadataJsonObject);
    this.extendedParameters = OidcUtils.getExtensionProperties(metadataJsonObject, this.baseMetadata);
  }

  /** Base metadata */
  @Getter @Setter T baseMetadata;

  /** Extended parameters not included in the base metadata object */
  @Getter @Setter private Map<String, Object> extendedParameters;

  /**
   * Get the value of an extended parameter
   *
   * @param parameterName name of the extended parameter
   * @return extended parameter value or null if no such parameter exists
   */
  public Object getExtendedParameter(String parameterName) {
    return extendedParameters.get(parameterName);
  }

  /**
   * Converts the extended metadata to a JSON object
   *
   * @return JSON object
   * @throws JsonProcessingException error processing JSON data
   */
  public Map<String, Object> toJsonObject() throws JsonProcessingException {
    Map<String, Object> baseMetadataObject = baseMetadata != null
      ? baseMetadata.toJsonObject()
      : new HashMap<>();
    return this.extendedParameters == null
      ? baseMetadataObject
      : mergeMetadata(baseMetadataObject);
  }

  private Map<String, Object> mergeMetadata(Map<String, Object> baseMetadataObject) {
    Map<String, Object> mergedMetadata = new HashMap<>(baseMetadataObject);
    extendedParameters.keySet()
      .forEach(s -> mergedMetadata.put(s, extendedParameters.get(s)));
    return mergedMetadata;
  }

  /**
   * Builder class for the specified base metadata type
   *
   * @param valueClass class of base metadata
   * @return extended metadata builder
   * @param <V> base metadata class
   */
  public static <V extends AbstractOidcFedMetadata> ExtendedMetadataBuilder<V> builder(Class<V> valueClass) {
    return new ExtendedMetadataBuilder<>();
  }

  /**
   * Builder for extended metadata
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
    public ExtendedMetadataBuilder<T> baseMetadata(T baseMetadata) {
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
    public ExtendedMetadataBuilder<T> addParameter(String parameterName, String value) {
      Map<String, Object> extendedParameters = Optional.ofNullable(this.extendedMetadata.getExtendedParameters())
        .orElse(new HashMap<>());
      extendedParameters.put(parameterName, value);
      this.extendedMetadata.extendedParameters = extendedParameters;
      return this;
    }

    /**
     * Build the extended metadata object
     * @return extended metadata
     */
    public ExtendedMetadata<T> build() {
      return extendedMetadata;
    }
  }

}
