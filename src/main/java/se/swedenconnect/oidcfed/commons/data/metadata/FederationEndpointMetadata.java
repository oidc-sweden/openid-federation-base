package se.swedenconnect.oidcfed.commons.data.metadata;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.oidcfed.commons.data.OidcLangJsonSerializer;

/**
 * Federation endpoint metadata
 */
public class FederationEndpointMetadata extends AbstractOidcFedMetadata {

  @JsonIgnore
  @Getter public static final OidcLangJsonSerializer<FederationEndpointMetadata> jsonSerializer =
    new OidcLangJsonSerializer<>(FederationEndpointMetadata.class);

  public FederationEndpointMetadata() {
    addLanguageParametersTags(List.of());
  }


  @JsonProperty("federation_fetch_endpoint")
  @Getter @Setter private String federationFetchEndpoint;

  @JsonProperty("federation_list_endpoint")
  @Getter @Setter private String federationListEndpoint;

  @JsonProperty("federation_resolve_endpoint")
  @Getter @Setter private String federationResolveEndpoint;

  @JsonProperty("federation_trust_mark_status_endpoint")
  @Getter @Setter private String federationTrustMarkStatusEndpoint;

  @JsonProperty("federation_trust_mark_list_endpoint")
  @Getter @Setter private String federationTrustMarkListEndpoint;

  @JsonProperty("federation_trust_mark_endpoint")
  @Getter @Setter private String federationTrustMarkEndpoint;

  @JsonProperty("federation_historical_keys_endpoint")
  @Getter @Setter private String federationHistoricalKeysEndpoint;

  @JsonProperty("federation_discovery_endpoint")
  @Getter @Setter private String federationDiscoveryEndpoint;


  /** {@inheritDoc} */
  @Override public String toJson(boolean prettyPrinting) throws JsonProcessingException {
    return jsonSerializer.setPrettyPrinting(prettyPrinting).toJson(this);
  }

  /** {@inheritDoc} */
  @Override public Map<String, Object> toJsonObject() throws JsonProcessingException {
    return jsonSerializer.toJsonObject(this);
  }

  /**
   * Creates builder class for Federation endpoint metadata
   * @return builder
   */
  public static FederationEndpointMetadataBuilder builder() {
    return new FederationEndpointMetadataBuilder();
  }

  /**
   * Builder class for federation endpoint metadata
   */
  public static class FederationEndpointMetadataBuilder
    extends AbstractOidcFedMetadataBuilder<FederationEndpointMetadata, FederationEndpointMetadataBuilder> {

    /**
     * Private constructor
     */
    private FederationEndpointMetadataBuilder() {
      super(new FederationEndpointMetadata());
    }

    public FederationEndpointMetadataBuilder federationFetchEndpoint(String federationFetchEndpoint){
      this.metadata.federationFetchEndpoint = federationFetchEndpoint;
      return this;
    }
    public FederationEndpointMetadataBuilder federationListEndpoint(String federationListEndpoint){
      this.metadata.federationListEndpoint = federationListEndpoint;
      return this;
    }
    public FederationEndpointMetadataBuilder federationResolveEndpoint(String federationResolveEndpoint){
      this.metadata.federationResolveEndpoint = federationResolveEndpoint;
      return this;
    }
    public FederationEndpointMetadataBuilder federationTrustMarkStatusEndpoint(String federationTrustMarkStatusEndpoint){
      this.metadata.federationTrustMarkStatusEndpoint = federationTrustMarkStatusEndpoint;
      return this;
    }
    public FederationEndpointMetadataBuilder federationTrustMarkListEndpoint(String federationTrustMarkListEndpoint){
      this.metadata.federationTrustMarkListEndpoint = federationTrustMarkListEndpoint;
      return this;
    }
    public FederationEndpointMetadataBuilder federationTrustMarkEndpoint(String federationTrustMarkEndpoint){
      this.metadata.federationTrustMarkEndpoint = federationTrustMarkEndpoint;
      return this;
    }
    public FederationEndpointMetadataBuilder federationHistoricalKeysEndpoint(String federationHistoricalKeysEndpoint){
      this.metadata.federationHistoricalKeysEndpoint = federationHistoricalKeysEndpoint;
      return this;
    }
    public FederationEndpointMetadataBuilder federationDiscoveryEndpoint(String federationDiscoveryEndpoint){
      this.metadata.federationDiscoveryEndpoint = federationDiscoveryEndpoint;
      return this;
    }

    /** {@inheritDoc} */
    @Override FederationEndpointMetadataBuilder getReturnedBuilderInstance() {
      return this;
    }

    /** {@inheritDoc} */
    @Override public FederationEndpointMetadata build() {
      return metadata;
    }
  }


}
