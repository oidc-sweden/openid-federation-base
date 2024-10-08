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

import java.util.List;

/**
 * Common metadata to Authorization Servers and OpenID Providers
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public abstract class BasicASMetadata extends AbstractOidcFedMetadata {

  public BasicASMetadata() {
    this.addLanguageParametersTags(List.of());
  }

  @JsonProperty("issuer")
  @Getter
  @Setter
  protected String issuer;

  @JsonProperty("authorization_endpoint")
  @Getter
  @Setter
  protected String authorizationEndpoint;

  @JsonProperty("token_endpoint")
  @Getter
  @Setter
  protected String tokenEndpoint;

  @JsonProperty("registration_endpoint")
  @Getter
  @Setter
  protected String registrationEndpoint;

  @JsonProperty("scopes_supported")
  @Getter
  @Setter
  protected List<String> scopesSupported;

  @JsonProperty("response_types_supported")
  @Getter
  @Setter
  protected List<String> responseTypesSupported;

  @JsonProperty("response_modes_supported")
  @Getter
  @Setter
  protected List<String> responseModesSupported;

  @JsonProperty("grant_types_supported")
  @Getter
  @Setter
  protected List<String> grantTypesSupported;

  @JsonProperty("token_endpoint_auth_methods_supported")
  @Getter
  @Setter
  protected List<String> tokenEndpointAuthMethodsSupported;

  @JsonProperty("token_endpoint_auth_signing_alg_values_supported")
  @Getter
  @Setter
  protected List<String> tokenEndpointAuthSigningAlgValuesSupported;

  @JsonProperty("service_documentation")
  @Getter
  @Setter
  protected String serviceDocumentation;

  @JsonProperty("ui_locales_supported")
  @Getter
  @Setter
  protected List<String> uiLocalesSupported;

  @JsonProperty("op_policy_uri")
  @Getter
  @Setter
  protected String opPolicyUri;

  @JsonProperty("op_tos_uri")
  @Getter
  @Setter
  protected String opTosUri;

  @JsonProperty("introspection_endpoint")
  @Getter
  @Setter
  protected String introspectionEndpoint;

  @JsonProperty("introspection_endpoint_auth_methods_supported")
  @Getter
  @Setter
  protected List<String> introspectionEndpointAuthMethodsSupported;

  @JsonProperty("introspection_endpoint_auth_signing_alg_values_supported")
  @Getter
  @Setter
  protected List<String> introspectionEndpointAuthSigningAlgValuesSupported;

  @JsonProperty("code_challenge_methods_supported")
  @Getter
  @Setter
  protected List<String> codeChallengeMethodsSupported;

  public static abstract class BasicASMetadataBuilder<T extends BasicASMetadata, B extends BasicASMetadataBuilder<?, ?>>
      extends AbstractOidcFedMetadataBuilder<T, B> {

    public BasicASMetadataBuilder(final T metadata) {
      super(metadata);
    }

    public B issuer(final String issuer) {
      this.metadata.issuer = issuer;
      return this.getReturnedBuilderInstance();
    }

    public B authorizationEndpoint(final String authorizationEndpoint) {
      this.metadata.authorizationEndpoint = authorizationEndpoint;
      return this.getReturnedBuilderInstance();
    }

    public B tokenEndpoint(final String tokenEndpoint) {
      this.metadata.tokenEndpoint = tokenEndpoint;
      return this.getReturnedBuilderInstance();
    }

    public B registrationEndpoint(final String registrationEndpoint) {
      this.metadata.registrationEndpoint = registrationEndpoint;
      return this.getReturnedBuilderInstance();
    }

    public B scopesSupported(final List<String> scopesSupported) {
      this.metadata.scopesSupported = scopesSupported;
      return this.getReturnedBuilderInstance();
    }

    public B responseTypesSupported(final List<String> responseTypesSupported) {
      this.metadata.responseTypesSupported = responseTypesSupported;
      return this.getReturnedBuilderInstance();
    }

    public B responseModesSupported(final List<String> responseModesSupported) {
      this.metadata.responseModesSupported = responseModesSupported;
      return this.getReturnedBuilderInstance();
    }

    public B grantTypesSupported(final List<String> grantTypesSupported) {
      this.metadata.grantTypesSupported = grantTypesSupported;
      return this.getReturnedBuilderInstance();
    }

    public B tokenEndpointAuthMethodsSupported(final List<String> tokenEndpointAuthMethodsSupported) {
      this.metadata.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported;
      return this.getReturnedBuilderInstance();
    }

    public B tokenEndpointAuthSigningAlgValuesSupported(final List<String> tokenEndpointAuthSigningAlgValuesSupported) {
      this.metadata.tokenEndpointAuthSigningAlgValuesSupported = tokenEndpointAuthSigningAlgValuesSupported;
      return this.getReturnedBuilderInstance();
    }

    public B serviceDocumentation(final String serviceDocumentation) {
      this.metadata.serviceDocumentation = serviceDocumentation;
      return this.getReturnedBuilderInstance();
    }

    public B uiLocalesSupported(final List<String> uiLocalesSupported) {
      this.metadata.uiLocalesSupported = uiLocalesSupported;
      return this.getReturnedBuilderInstance();
    }

    public B opPolicyUri(final String opPolicyUri) {
      this.metadata.opPolicyUri = opPolicyUri;
      return this.getReturnedBuilderInstance();
    }

    public B opTosUri(final String opTosUri) {
      this.metadata.opTosUri = opTosUri;
      return this.getReturnedBuilderInstance();
    }

    public B introspectionEndpoint(final String introspectionEndpoint) {
      this.metadata.introspectionEndpoint = introspectionEndpoint;
      return this.getReturnedBuilderInstance();
    }

    public B introspectionEndpointAuthMethodsSupported(final List<String> introspectionEndpointAuthMethodsSupported) {
      this.metadata.introspectionEndpointAuthMethodsSupported = introspectionEndpointAuthMethodsSupported;
      return this.getReturnedBuilderInstance();
    }

    public B introspectionEndpointAuthSigningAlgValuesSupported(
        final List<String> introspectionEndpointAuthSigningAlgValuesSupported) {
      this.metadata.introspectionEndpointAuthSigningAlgValuesSupported =
          introspectionEndpointAuthSigningAlgValuesSupported;
      return this.getReturnedBuilderInstance();
    }

    private List<String> codeChallengeMethodsSupported;

    public B codeChallengeMethodsSupported(final List<String> codeChallengeMethodsSupported) {
      this.metadata.codeChallengeMethodsSupported = codeChallengeMethodsSupported;
      return this.getReturnedBuilderInstance();
    }

  }

}
