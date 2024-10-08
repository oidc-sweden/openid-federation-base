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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;
import se.oidc.oidfed.base.data.LanguageObject;

import java.util.List;

/**
 * Common metadata Oauth clients and OpenID relying parties
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public abstract class BasicClientMetadata extends AbstractOidcFedMetadata {

  /**
   * REQUIRED. Array of Redirection URI values used by the Client. One of these registered Redirection URI values MUST
   * exactly match the redirect_uri parameter value used in each Authorization Request, with the matching performed as
   * described in Section 6.2.1 of [RFC3986] (Simple String Comparison).
   */
  @JsonProperty("redirect_uris")
  @Getter
  @Setter
  protected List<String> redirectUris;

  /**
   * OPTIONAL. Requested Client Authentication method for the Token Endpoint. The options are client_secret_post,
   * client_secret_basic, client_secret_jwt, private_key_jwt, and none, as described in Section 9 of OpenID Connect Core
   * 1.0 [OpenID.Core]. Other authentication methods MAY be defined by extensions. If omitted, the default is
   * client_secret_basic -- the HTTP Basic Authentication Scheme specified in Section 2.3.1 of OAuth 2.0 [RFC6749].
   */
  @JsonProperty("token_endpoint_auth_method")
  @Getter
  @Setter
  protected String tokenEndpointAuthMethod;

  /**
   * OPTIONAL. JSON array containing a list of the OAuth 2.0 Grant Types that the Client is declaring that it will
   * restrict itself to using. The Grant Type values used by OpenID Connect are:
   *
   * <ul>
   *   <li>authorization_code: The Authorization Code Grant Type described in OAuth 2.0 Section 4.1.</li>
   *   <li>implicit: The Implicit Grant Type described in OAuth 2.0 Section 4.2.</li>
   *   <li>refresh_token: The Refresh Token Grant Type described in OAuth 2.0 Section 6.*</li>
   * </ul>
   */
  @JsonProperty("grant_types")
  @Getter
  @Setter
  protected List<String> grantTypes;

  /**
   * OPTIONAL. JSON array containing a list of the OAuth 2.0 response_type values that the Client is declaring that it
   * will restrict itself to using. If omitted, the default is that the Client will use only the code Response Type.
   */
  @JsonProperty("response_types")
  @Getter
  @Setter
  protected List<String> responseTypes;

  /**
   * OPTIONAL. Name of the Client to be presented to the End-User. If desired, representation of this Claim in different
   * languages and scripts is represented as described in Section 2.1.
   */
  @JsonProperty("client_name")
  @Getter
  @Setter
  protected LanguageObject<String> clientName;

  /**
   * OPTIONAL. URL of the home page of the Client. The value of this field MUST point to a valid Web page. If present,
   * the server SHOULD display this URL to the End-User in a followable fashion. If desired, representation of this
   * Claim in different languages and scripts is represented as described in Section 2.1.
   */
  @JsonProperty("client_uri")
  @Getter
  @Setter
  protected String clientUri;

  /**
   * OPTIONAL. URL that the Relying Party Client provides to the End-User to read about the Relying Party's terms of
   * service. The value of this field MUST point to a valid web page. The OpenID Provider SHOULD display this URL to the
   * End-User if it is given. If desired, representation of this Claim in different languages and scripts is represented
   * as described in Section 2.1.
   */
  @JsonProperty("tos_uri")
  @Getter
  @Setter
  protected LanguageObject<String> tosUri;

  /**
   * Constructor
   */
  public BasicClientMetadata() {
    this.addLanguageParametersTags(List.of("client_name", "tos_uri"));
  }

  /**
   * Builder class
   *
   * @param <T> Type of metadata
   * @param <B> Type of builder
   */
  public static abstract class BasicClientMetadataBuilder<T extends BasicClientMetadata, B extends BasicClientMetadataBuilder<?, ?>>
      extends AbstractOidcFedMetadataBuilder<T, B> {

    /**
     * Constructor
     *
     * @param metadata empty metadata object to populate with values from this builder
     */
    public BasicClientMetadataBuilder(final T metadata) {
      super(metadata);
    }

    /*
     * Setters
     */
    public B redirectUris(final List<String> redirectUris) {
      this.metadata.redirectUris = redirectUris;
      return this.getReturnedBuilderInstance();
    }

    public B tokenEndpointAuthMethod(final String tokenEndpointAuthMethod) {
      this.metadata.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
      return this.getReturnedBuilderInstance();
    }

    public B grantTypes(final List<String> grantTypes) {
      this.metadata.grantTypes = grantTypes;
      return this.getReturnedBuilderInstance();
    }

    public B responseTypes(final List<String> responseTypes) {
      this.metadata.responseTypes = responseTypes;
      return this.getReturnedBuilderInstance();
    }

    public B clientName(final LanguageObject<String> clientName) {
      this.metadata.clientName = clientName;
      return this.getReturnedBuilderInstance();
    }

    public B clientUri(final String clientUri) {
      this.metadata.clientUri = clientUri;
      return this.getReturnedBuilderInstance();
    }

    public B tosUri(final LanguageObject<String> tosUri) {
      this.metadata.tosUri = tosUri;
      return this.getReturnedBuilderInstance();
    }

  }

}
