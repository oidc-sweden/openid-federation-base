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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.Getter;
import lombok.Setter;
import se.oidc.oidfed.base.data.OidcLangJsonSerializer;

import java.util.List;
import java.util.Map;

/**
 * Federation endpoint metadata
 */
public class FederationEntityMetadata extends AbstractOidcFedMetadata {

  @JsonIgnore
  @Getter
  public static final OidcLangJsonSerializer<FederationEntityMetadata> jsonSerializer =
      new OidcLangJsonSerializer<>(FederationEntityMetadata.class);

  public FederationEntityMetadata() {
    this.addLanguageParametersTags(List.of());
  }

  @JsonProperty("federation_fetch_endpoint")
  @Getter
  @Setter
  private String federationFetchEndpoint;

  @JsonProperty("federation_list_endpoint")
  @Getter
  @Setter
  private String federationListEndpoint;

  @JsonProperty("federation_resolve_endpoint")
  @Getter
  @Setter
  private String federationResolveEndpoint;

  @JsonProperty("federation_trust_mark_status_endpoint")
  @Getter
  @Setter
  private String federationTrustMarkStatusEndpoint;

  @JsonProperty("federation_trust_mark_list_endpoint")
  @Getter
  @Setter
  private String federationTrustMarkListEndpoint;

  @JsonProperty("federation_trust_mark_endpoint")
  @Getter
  @Setter
  private String federationTrustMarkEndpoint;

  @JsonProperty("federation_historical_keys_endpoint")
  @Getter
  @Setter
  private String federationHistoricalKeysEndpoint;

  @JsonProperty("federation_discovery_endpoint")
  @Getter
  @Setter
  private String federationDiscoveryEndpoint;

  /** {@inheritDoc} */
  @Override
  public String toJson(final boolean prettyPrinting) throws JsonProcessingException {
    return jsonSerializer.setPrettyPrinting(prettyPrinting).toJson(this);
  }

  /** {@inheritDoc} */
  @Override
  public Map<String, Object> toJsonObject() throws JsonProcessingException {
    return jsonSerializer.toJsonObject(this);
  }

  /**
   * Creates builder class for Federation endpoint metadata
   *
   * @return builder
   */
  public static FederationEntityMetadataBuilder builder() {
    return new FederationEntityMetadataBuilder();
  }

  /**
   * Builder class for federation endpoint metadata
   */
  public static class FederationEntityMetadataBuilder
      extends AbstractOidcFedMetadataBuilder<FederationEntityMetadata, FederationEntityMetadataBuilder> {

    /**
     * Private constructor
     */
    private FederationEntityMetadataBuilder() {
      super(new FederationEntityMetadata());
    }

    public FederationEntityMetadataBuilder federationFetchEndpoint(final String federationFetchEndpoint) {
      this.metadata.federationFetchEndpoint = federationFetchEndpoint;
      return this;
    }

    public FederationEntityMetadataBuilder federationListEndpoint(final String federationListEndpoint) {
      this.metadata.federationListEndpoint = federationListEndpoint;
      return this;
    }

    public FederationEntityMetadataBuilder federationResolveEndpoint(final String federationResolveEndpoint) {
      this.metadata.federationResolveEndpoint = federationResolveEndpoint;
      return this;
    }

    public FederationEntityMetadataBuilder federationTrustMarkStatusEndpoint(
        final String federationTrustMarkStatusEndpoint) {
      this.metadata.federationTrustMarkStatusEndpoint = federationTrustMarkStatusEndpoint;
      return this;
    }

    public FederationEntityMetadataBuilder federationTrustMarkListEndpoint(
        final String federationTrustMarkListEndpoint) {
      this.metadata.federationTrustMarkListEndpoint = federationTrustMarkListEndpoint;
      return this;
    }

    public FederationEntityMetadataBuilder federationTrustMarkEndpoint(final String federationTrustMarkEndpoint) {
      this.metadata.federationTrustMarkEndpoint = federationTrustMarkEndpoint;
      return this;
    }

    public FederationEntityMetadataBuilder federationHistoricalKeysEndpoint(
        final String federationHistoricalKeysEndpoint) {
      this.metadata.federationHistoricalKeysEndpoint = federationHistoricalKeysEndpoint;
      return this;
    }

    public FederationEntityMetadataBuilder federationDiscoveryEndpoint(final String federationDiscoveryEndpoint) {
      this.metadata.federationDiscoveryEndpoint = federationDiscoveryEndpoint;
      return this;
    }

    /** {@inheritDoc} */
    @Override
    protected FederationEntityMetadataBuilder getReturnedBuilderInstance() {
      return this;
    }

    /** {@inheritDoc} */
    @Override
    public FederationEntityMetadata build() {
      return this.metadata;
    }
  }

}
