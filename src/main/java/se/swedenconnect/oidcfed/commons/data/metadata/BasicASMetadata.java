package se.swedenconnect.oidcfed.commons.data.metadata;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.Setter;

/**
 * Common metadata to Authorization Servers and OpenID Providers
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public abstract class BasicASMetadata extends AbstractOidcFedMetadata {

  public BasicASMetadata() {
    addLanguageParametersTags(List.of());
  }

  @JsonProperty("issuer")
  @Getter @Setter protected String issuer;

  @JsonProperty("authorization_endpoint")
  @Getter @Setter protected String authorizationEndpoint;

  @JsonProperty("token_endpoint")
  @Getter @Setter protected String tokenEndpoint;

  @JsonProperty("registration_endpoint")
  @Getter @Setter protected String registrationEndpoint;

  @JsonProperty("scopes_supported")
  @Getter @Setter protected List<String> scopesSupported;

  @JsonProperty("response_types_supported")
  @Getter @Setter protected List<String> responseTypesSupported;

  @JsonProperty("response_modes_supported")
  @Getter @Setter protected List<String> responseModesSupported;

  @JsonProperty("grant_types_supported")
  @Getter @Setter protected List<String> grantTypesSupported;

  @JsonProperty("token_endpoint_auth_methods_supported")
  @Getter @Setter protected List<String> tokenEndpointAuthMethodsSupported;

  @JsonProperty("token_endpoint_auth_signing_alg_values_supported")
  @Getter @Setter protected List<String> tokenEndpointAuthSigningAlgValuesSupported;

  @JsonProperty("service_documentation")
  @Getter @Setter protected String serviceDocumentation;

  @JsonProperty("ui_locales_supported")
  @Getter @Setter protected List<String> uiLocalesSupported;

  @JsonProperty("op_policy_uri")
  @Getter @Setter protected String opPolicyUri;

  @JsonProperty("op_tos_uri")
  @Getter @Setter protected String opTosUri;

  @JsonProperty("introspection_endpoint")
  @Getter @Setter protected String introspectionEndpoint;

  @JsonProperty("introspection_endpoint_auth_methods_supported")
  @Getter @Setter protected List<String> introspectionEndpointAuthMethodsSupported;

  @JsonProperty("introspection_endpoint_auth_signing_alg_values_supported")
  @Getter @Setter protected List<String> introspectionEndpointAuthSigningAlgValuesSupported;

  @JsonProperty("code_challenge_methods_supported")
  @Getter @Setter protected List<String> codeChallengeMethodsSupported;



  public static abstract class BasicASMetadataBuilder<T extends BasicASMetadata, B extends BasicASMetadataBuilder<?,?>>
    extends AbstractOidcFedMetadataBuilder<T, B> {

    public BasicASMetadataBuilder(T metadata) {
      super(metadata);
    }

    public B issuer(String issuer) {
      this.metadata.issuer = issuer;
      return getReturnedBuilderInstance();
    }

    public B authorizationEndpoint(String authorizationEndpoint) {
      this.metadata.authorizationEndpoint = authorizationEndpoint;
      return getReturnedBuilderInstance();
    }
    public B tokenEndpoint(String tokenEndpoint) {
      this.metadata.tokenEndpoint = tokenEndpoint;
      return getReturnedBuilderInstance();
    }

    public B registrationEndpoint(String registrationEndpoint) {
      this.metadata.registrationEndpoint = registrationEndpoint;
      return getReturnedBuilderInstance();
    }

    public B scopesSupported(List<String> scopesSupported) {
      this.metadata.scopesSupported = scopesSupported;
      return getReturnedBuilderInstance();
    }

    public B responseTypesSupported(List<String> responseTypesSupported) {
      this.metadata.responseTypesSupported = responseTypesSupported;
      return getReturnedBuilderInstance();
    }
    public B responseModesSupported(List<String> responseModesSupported) {
      this.metadata.responseModesSupported = responseModesSupported;
      return getReturnedBuilderInstance();
    }
    public B grantTypesSupported(List<String> grantTypesSupported) {
      this.metadata.grantTypesSupported = grantTypesSupported;
      return getReturnedBuilderInstance();
    }
    public B tokenEndpointAuthMethodsSupported(List<String> tokenEndpointAuthMethodsSupported) {
      this.metadata.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported;
      return getReturnedBuilderInstance();
    }
    public B tokenEndpointAuthSigningAlgValuesSupported(List<String> tokenEndpointAuthSigningAlgValuesSupported) {
      this.metadata.tokenEndpointAuthSigningAlgValuesSupported = tokenEndpointAuthSigningAlgValuesSupported;
      return getReturnedBuilderInstance();
    }
    public B serviceDocumentation(String serviceDocumentation) {
      this.metadata.serviceDocumentation = serviceDocumentation;
      return getReturnedBuilderInstance();
    }
    public B uiLocalesSupported(List<String> uiLocalesSupported) {
      this.metadata.uiLocalesSupported = uiLocalesSupported;
      return getReturnedBuilderInstance();
    }
    public B opPolicyUri(String opPolicyUri) {
      this.metadata.opPolicyUri = opPolicyUri;
      return getReturnedBuilderInstance();
    }
    public B opTosUri(String opTosUri) {
      this.metadata.opTosUri = opTosUri;
      return getReturnedBuilderInstance();
    }
    public B introspectionEndpoint(String introspectionEndpoint) {
      this.metadata.introspectionEndpoint = introspectionEndpoint;
      return getReturnedBuilderInstance();
    }

    public B introspectionEndpointAuthMethodsSupported(List<String> introspectionEndpointAuthMethodsSupported) {
      this.metadata.introspectionEndpointAuthMethodsSupported = introspectionEndpointAuthMethodsSupported;
      return getReturnedBuilderInstance();
    }

    public B introspectionEndpointAuthSigningAlgValuesSupported(List<String> introspectionEndpointAuthSigningAlgValuesSupported) {
      this.metadata.introspectionEndpointAuthSigningAlgValuesSupported = introspectionEndpointAuthSigningAlgValuesSupported;
      return getReturnedBuilderInstance();
    }

    private List<String> codeChallengeMethodsSupported;
    public B codeChallengeMethodsSupported(List<String> codeChallengeMethodsSupported) {
      this.metadata.codeChallengeMethodsSupported = codeChallengeMethodsSupported;
      return getReturnedBuilderInstance();
    }

  }

}
