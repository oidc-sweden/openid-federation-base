package se.swedenconnect.oidcfed.commons.data.metadata;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.JsonProcessingException;

import lombok.Getter;
import se.swedenconnect.oidcfed.commons.data.OidcLangJsonSerializer;

/**
 * Resource server metadata
 */
public class ResourceServerMetadata extends AbstractOidcFedMetadata {

  @JsonIgnore
  @Getter private static final OidcLangJsonSerializer<ResourceServerMetadata> jsonSerializer =
    new OidcLangJsonSerializer<>(ResourceServerMetadata.class);

  /**
   * Constructor
   */
  public ResourceServerMetadata() {
    addLanguageParametersTags(List.of());
  }

  /** {@inheritDoc} */
  @Override public String toJson(boolean prettyPrinting) throws JsonProcessingException {
    return jsonSerializer.setPrettyPrinting(prettyPrinting).toJson(this);
  }

  /** {@inheritDoc} */
  @Override public Map<String, Object> toJsonObject() throws JsonProcessingException {
    return jsonSerializer.toJsonObject(this);
  }

  /**
   * Create builder for Resource Server metadata
   * @return
   */
  public static ResourceServerMetadataBuilder builder() {
    return new ResourceServerMetadataBuilder();
  }

  /**
   * Builder class for resource server metadata
   */
  public static class ResourceServerMetadataBuilder
    extends AbstractOidcFedMetadataBuilder<ResourceServerMetadata, ResourceServerMetadataBuilder> {

    /**
     * Private constructor
     */
    private ResourceServerMetadataBuilder() {
      super(new ResourceServerMetadata());
    }

    /** {@inheritDoc} */
    @Override ResourceServerMetadataBuilder getReturnedBuilderInstance() {
      return this;
    }

    /** {@inheritDoc} */
    @Override public ResourceServerMetadata build() {
      return metadata;
    }
  }
}
