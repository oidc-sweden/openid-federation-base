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
 * Oauth client metadata
 */
public class ClientMetadata extends BasicClientMetadata {

  @JsonIgnore
  @Getter
  private static final OidcLangJsonSerializer<ClientMetadata> jsonSerializer =
      new OidcLangJsonSerializer<>(ClientMetadata.class);

  /**
   * String containing a space-separated list of scope values (as described in Section 3.3 of OAuth 2.0 [RFC6749]) that
   * the client can use when requesting access tokens.  The semantics of values in this list are service specific.  If
   * omitted, an authorization server MAY register a client with a default set of scopes.
   */
  @JsonProperty("scope")
  @Getter
  @Setter
  private String scope;

  /**
   * A unique identifier string (e.g., a Universally Unique Identifier (UUID)) assigned by the client developer or
   * software publisher used by registration endpoints to identify the client software to be dynamically registered.
   */
  @JsonProperty("software_id")
  @Getter
  @Setter
  private String softwareId;

  /**
   * A version identifier string for the client software identified by "software_id".
   */
  @JsonProperty("software_version")
  @Getter
  @Setter
  private String softwareVersion;

  /**
   * Constructor
   */
  public ClientMetadata() {
    this.addLanguageParametersTags(List.of());
  }

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
   * Create builder for this metadata object
   *
   * @return builder
   */
  public static ClientMetadataBuilder builder() {
    return new ClientMetadataBuilder();
  }

  /**
   * Client metadata builder class
   */
  public static class ClientMetadataBuilder extends BasicClientMetadataBuilder<ClientMetadata, ClientMetadataBuilder> {

    /**
     * Constructor
     */
    private ClientMetadataBuilder() {
      super(new ClientMetadata());
    }

    @Override
    ClientMetadataBuilder getReturnedBuilderInstance() {
      return this;
    }

    public ClientMetadataBuilder scope(final String scope) {
      this.metadata.scope = scope;
      return this;
    }

    public ClientMetadataBuilder softwareId(final String softwareId) {
      this.metadata.softwareId = softwareId;
      return this;
    }

    public ClientMetadataBuilder softwareVersion(final String softwareVersion) {
      this.metadata.softwareVersion = softwareVersion;
      return this;
    }

    @Override
    public ClientMetadata build() {
      return this.metadata;
    }
  }

}
