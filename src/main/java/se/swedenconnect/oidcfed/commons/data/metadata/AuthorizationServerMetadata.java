package se.swedenconnect.oidcfed.commons.data.metadata;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.oidcfed.commons.data.OidcLangJsonSerializer;

/**
 * Authorization server metadata
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthorizationServerMetadata extends BasicASMetadata {

  @JsonIgnore
  @Getter private static final OidcLangJsonSerializer<AuthorizationServerMetadata> jsonSerializer =
    new OidcLangJsonSerializer<>(AuthorizationServerMetadata.class);

  /*
   * Metadata parameters defined in this extension to BasicASMetadata
   */
  @JsonProperty("revocation_endpoint")
  @Getter @Setter private String revocationEndpoint;

  @JsonProperty("revocation_endpoint_auth_methods_supported")
  @Getter @Setter private List<String> revocationEndpointAuthMethodsSupported;

  @JsonProperty("revocation_endpoint_auth_signing_alg_values_supported")
  @Getter @Setter private List<String> revocationEndpointAuthSigningAlgValuesSupported;

  /**
   * Constructor
   */
  public AuthorizationServerMetadata() {
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
   * Creates builder class
   * @return builder
   */
  public static AuthorizationServerMetadataBuilder builder() {
    return new AuthorizationServerMetadataBuilder();
  }

  /**
   * Builder class
   */
  public static class AuthorizationServerMetadataBuilder
    extends BasicASMetadataBuilder<AuthorizationServerMetadata, AuthorizationServerMetadataBuilder> {

    /**
     * Private constructor
     */
    private AuthorizationServerMetadataBuilder() {
      super(new AuthorizationServerMetadata());
    }

    /** {@inheritDoc} */
    @Override AuthorizationServerMetadataBuilder getReturnedBuilderInstance() {
      return this;
    }

    public AuthorizationServerMetadataBuilder revocationEndpoint(String revocationEndpoint) {
      this.metadata.revocationEndpoint = revocationEndpoint;
      return this;
    }
    public AuthorizationServerMetadataBuilder revocationEndpointAuthMethodsSupported(List<String> revocationEndpointAuthMethodsSupported) {
      this.metadata.revocationEndpointAuthMethodsSupported = revocationEndpointAuthMethodsSupported;
      return this;
    }
    public AuthorizationServerMetadataBuilder revocationEndpointAuthSigningAlgValuesSupported(List<String> revocationEndpointAuthSigningAlgValuesSupported) {
      this.metadata.revocationEndpointAuthSigningAlgValuesSupported = revocationEndpointAuthSigningAlgValuesSupported;
      return this;
    }

    /** {@inheritDoc} */
    @Override public AuthorizationServerMetadata build() {
      return metadata;
    }
  }


}
