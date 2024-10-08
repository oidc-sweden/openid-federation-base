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
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.Getter;
import lombok.Setter;
import se.oidc.oidfed.base.data.OidcLangJsonSerializer;

import java.util.List;
import java.util.Map;

/**
 * Relying party metadata
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OpMetadata extends BasicASMetadata {

  @JsonIgnore
  @Getter
  private static final OidcLangJsonSerializer<OpMetadata> jsonSerializer =
      new OidcLangJsonSerializer<>(OpMetadata.class);

  /**
   * OpenID Federation REQUIRED. Array specifying the federation types supported. Federation-type values defined by this
   * specification are automatic and explicit. Additional values MAY be defined and used, without restriction by this
   * specification.
   */
  @JsonProperty("client_registration_types_supported")
  @Getter
  @Setter
  private List<List<?>> clientRegistrationTypesSupported;

  /**
   * OpenID Federation OPTIONAL. URL of the OP's federation-specific Dynamic Client Registration Endpoint. If the OP
   * supports Explicit Client Registration Endpoint this URL MUST use the https scheme and MAY contain port, path, and
   * query parameter components. If the OP supports Explicit Client Registration as described in Section 12.2, then this
   * claim is REQUIRED.
   */
  @JsonProperty("federation_registration_endpoint")
  @Getter
  @Setter
  private String federationRegistrationEndpoint;

  /**
   * OpenID Federation OPTIONAL.The request_authentication_methods_supported value is a JSON object where the member
   * names are names of endpoints where the request authentication occurs. This MAY be either at the OP's Authorization
   * Endpoint or the OP's Pushed Authorization Request (PAR) endpoint. Supported endpoint identifiers are
   * authorization_endpoint and pushed_authorization_request_endpoint. The values of the JSON object members for the
   * endpoint names are JSON arrays containing the names of the request authentication methods used at those endpoints.
   * Valid values are private_key_jwt, tls_client_auth, self_signed_tls_client_auth, request_object. Other values may be
   * used.
   */
  @JsonProperty("request_authentication_methods_supported")
  @Getter
  @Setter
  private Map<String, List<String>> requestAuthenticationMethodsSupported;

  /**
   * OpenID Federation OPTIONAL. JSON array containing a list of the supported JWS [RFC7515] algorithms (alg values) for
   * signing the JWT [RFC7519] used in the Request Object contained in the request parameter of an authorization request
   * or in the private_key_jwt of a pushed authorization request. This entry MUST be present if either of these
   * authentication methods are specified in the request_authentication_methods_supported entry.
   */
  @JsonProperty("request_authentication_signing_alg_values_supported")
  @Getter
  @Setter
  private List<String> requestAuthenticationSigningAlgValuesSupported;

  /**
   * RECOMMENDED. URL of the OP's UserInfo Endpoint [OpenID.Core]. This URL MUST use the https scheme and MAY contain
   * port, path, and query parameter components.
   */
  @JsonProperty("userinfo_endpoint")
  @Getter
  @Setter
  private String userinfoEndpoint;

  /**
   * OPTIONAL. JSON array containing a list of the Authentication Context Class References that this OP supports.
   */
  @JsonProperty("acr_values_supported")
  @Getter
  @Setter
  private List<String> acrValuesSupported;

  /**
   * REQUIRED. JSON array containing a list of the Subject Identifier types that this OP supports. Valid types include
   * pairwise and public.
   */
  @JsonProperty("subject_types_supported")
  @Getter
  @Setter
  private List<String> subjectTypesSupported;

  /**
   * REQUIRED. JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for the ID
   * Token to encode the Claims in a JWT [JWT]. The algorithm RS256 MUST be included. The value none MAY be supported,
   * but MUST NOT be used unless the Response Type used returns no ID Token from the Authorization Endpoint (such as
   * when using the Authorization Code Flow).
   */
  @JsonProperty("id_token_signing_alg_values_supported")
  @Getter
  @Setter
  private List<String> idTokenSigningAlgValuesSupported;

  /**
   * OPTIONAL. JSON array containing a list of the JWE encryption algorithms (alg values) supported by the OP for the ID
   * Token to encode the Claims in a JWT [JWT].
   */
  @JsonProperty("id_token_encryption_alg_values_supported")
  @Getter
  @Setter
  private List<String> idTokenEncryptionAlgValuesSupported;

  /**
   * OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for the ID
   * Token to encode the Claims in a JWT [JWT].
   */
  @JsonProperty("id_token_encryption_enc_values_supported")
  @Getter
  @Setter
  private List<String> idTokenEncryptionEncValuesSupported;

  /**
   * OPTIONAL. JSON array containing a list of the JWS [JWS] signing algorithms (alg values) [JWA] supported by the
   * UserInfo Endpoint to encode the Claims in a JWT [JWT]. The value none MAY be included.
   */
  @JsonProperty("userinfo_signing_alg_values_supported")
  @Getter
  @Setter
  private List<String> userinfoSigningAlgValuesSupported;

  /**
   * OPTIONAL. JSON array containing a list of the JWE [JWE] encryption algorithms (alg values) [JWA] supported by the
   * UserInfo Endpoint to encode the Claims in a JWT [JWT].
   */
  @JsonProperty("userinfo_encryption_alg_values_supported")
  @Getter
  @Setter
  private List<String> userinfoEncryptionAlgValuesSupported;

  /**
   * OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) [JWA] supported by the
   * UserInfo Endpoint to encode the Claims in a JWT [JWT].
   */
  @JsonProperty("userinfo_encryption_enc_values_supported")
  @Getter
  @Setter
  private List<String> userinfoEncryptionEncValuesSupported;

  /**
   * OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for Request
   * Objects, which are described in Section 6.1 of OpenID Connect Core 1.0 [OpenID.Core]. These algorithms are used
   * both when the Request Object is passed by value (using the request parameter) and when it is passed by reference
   * (using the request_uri parameter). Servers SHOULD support none and RS256.
   */
  @JsonProperty("request_object_signing_alg_values_supported")
  @Getter
  @Setter
  private List<String> requestObjectSigningAlgValuesSupported;

  /**
   * OPTIONAL. JSON array containing a list of the JWE encryption algorithms (alg values) supported by the OP for
   * Request Objects. These algorithms are used both when the Request Object is passed by value and when it is passed by
   * reference.
   */
  @JsonProperty("request_object_encryption_alg_values_supported")
  @Getter
  @Setter
  private List<String> requestObjectEncryptionAlgValuesSupported;

  /**
   * OPTIONAL. JSON array containing a list of the JWE encryption algorithms (enc values) supported by the OP for
   * Request Objects. These algorithms are used both when the Request Object is passed by value and when it is passed by
   * reference.
   */
  @JsonProperty("request_object_encryption_enc_values_supported")
  @Getter
  @Setter
  private List<String> requestObjectEncryptionEncValuesSupported;

  /**
   * OPTIONAL. JSON array containing a list of the display parameter values that the OpenID Provider supports. These
   * values are described in Section 3.1.2.1 of OpenID Connect Core 1.0 [OpenID.Core].
   */
  @JsonProperty("display_values_supported")
  @Getter
  @Setter
  private List<String> displayValuesSupported;

  /**
   * OPTIONAL. JSON array containing a list of the Claim Types that the OpenID Provider supports. These Claim Types are
   * described in Section 5.6 of OpenID Connect Core 1.0 [OpenID.Core]. Values defined by this specification are normal,
   * aggregated, and distributed. If omitted, the implementation supports only normal Claims.
   */
  @JsonProperty("claim_types_supported")
  @Getter
  @Setter
  private List<String> claimTypesSupported;

  /**
   * RECOMMENDED. JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able to
   * supply values for. Note that for privacy or other reasons, this might not be an exhaustive list.
   */
  @JsonProperty("claims_supported")
  @Getter
  @Setter
  private List<String> claimsSupported;

  /**
   * OPTIONAL. Languages and scripts supported for values in Claims being returned, represented as a JSON array of BCP47
   * [RFC5646] language tag values. Not all languages and scripts are necessarily supported for all Claim values.
   */
  @JsonProperty("claims_locales_supported")
  @Getter
  @Setter
  private List<String> claimsLocalesSupported;

  /**
   * OPTIONAL. Boolean value specifying whether the OP supports use of the claims parameter, with true indicating
   * support. If omitted, the default value is false.
   */
  @JsonProperty("claims_parameter_supported")
  @Getter
  @Setter
  private Boolean claimsParameterSupported;

  /**
   * OPTIONAL. Boolean value specifying whether the OP supports use of the request parameter, with true indicating
   * support. If omitted, the default value is false.
   */
  @JsonProperty("request_parameter_supported")
  @Getter
  @Setter
  private Boolean requestParameterSupported;

  /**
   * OPTIONAL. Boolean value specifying whether the OP supports use of the request_uri parameter, with true indicating
   * support. If omitted, the default value is true.
   */
  @JsonProperty("request_uri_parameter_supported")
  @Getter
  @Setter
  private Boolean requestUriParameterSupported;

  /**
   * OPTIONAL. Boolean value specifying whether the OP requires any request_uri values used to be pre-registered using
   * the request_uris registration parameter. Pre-registration is REQUIRED when the value is true. If omitted, the
   * default value is false.
   */
  @JsonProperty("require_request_uri_registration")
  @Getter
  @Setter
  private Boolean requireRequestUriRegistration;

  /**
   * A discovery parameter specifying whether the OpenID Provider supports the https://id.oidc.se/param/userMessage
   * authentication request parameter
   */
  @JsonProperty("https://id.oidc.se/disco/userMessageSupported")
  @Getter
  @Setter
  private Boolean oidcSeDiscoUserMessageSupported;

  /**
   * Holds the User Message MIME type(s) that is supported by the OpenID Provider. Its value is only relevant if
   * https://id.oidc.se/disco/userMessageSupported is set to true
   */
  @JsonProperty("https://id.oidc.se/disco/userMessageSupportedMimeTypes")
  @Getter
  @Setter
  private List<String> oidcSeDiscoUserMessageSupportedMimeTypes;

  /**
   * A discovery parameter specifying whether the OpenID Provider supports the https://id.oidc.se/param/authnProvider
   * authentication request parameter
   */
  @JsonProperty("https://id.oidc.se/disco/authnProviderSupported")
  @Getter
  @Setter
  private Boolean oidcSeDiscoAuthnProviderSupported;

  /**
   * Constructor
   */
  public OpMetadata() {
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
   * Creates a builder for OP metadata
   *
   * @return builder
   */
  public static OpMetadataBuilder builder() {
    return new OpMetadataBuilder();
  }

  /**
   * OP metadata builder class
   */
  public static class OpMetadataBuilder extends BasicASMetadataBuilder<OpMetadata, OpMetadataBuilder> {

    /**
     * Private constructor
     */
    private OpMetadataBuilder() {
      super(new OpMetadata());
    }

    /** {@inheritDoc} */
    @Override
    OpMetadataBuilder getReturnedBuilderInstance() {
      return this;
    }

    public OpMetadataBuilder userinfoEndpoint(final String userinfoEndpoint) {
      this.metadata.userinfoEndpoint = userinfoEndpoint;
      return this;
    }

    public OpMetadataBuilder acrValuesSupported(final List<String> acrValuesSupported) {
      this.metadata.acrValuesSupported = acrValuesSupported;
      return this;
    }

    public OpMetadataBuilder subjectTypesSupported(final List<String> subjectTypesSupported) {
      this.metadata.subjectTypesSupported = subjectTypesSupported;
      return this;
    }

    public OpMetadataBuilder idTokenSigningAlgValuesSupported(final List<String> idTokenSigningAlgValuesSupported) {
      this.metadata.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported;
      return this;
    }

    public OpMetadataBuilder idTokenEncryptionAlgValuesSupported(
        final List<String> idTokenEncryptionAlgValuesSupported) {
      this.metadata.idTokenEncryptionAlgValuesSupported = idTokenEncryptionAlgValuesSupported;
      return this;
    }

    public OpMetadataBuilder idTokenEncryptionEncValuesSupported(
        final List<String> idTokenEncryptionEncValuesSupported) {
      this.metadata.idTokenEncryptionEncValuesSupported = idTokenEncryptionEncValuesSupported;
      return this;
    }

    public OpMetadataBuilder userinfoSigningAlgValuesSupported(final List<String> userinfoSigningAlgValuesSupported) {
      this.metadata.userinfoSigningAlgValuesSupported = userinfoSigningAlgValuesSupported;
      return this;
    }

    public OpMetadataBuilder userinfoEncryptionAlgValuesSupported(
        final List<String> userinfoEncryptionAlgValuesSupported) {
      this.metadata.userinfoEncryptionAlgValuesSupported = userinfoEncryptionAlgValuesSupported;
      return this;
    }

    public OpMetadataBuilder userinfoEncryptionEncValuesSupported(
        final List<String> userinfoEncryptionEncValuesSupported) {
      this.metadata.userinfoEncryptionEncValuesSupported = userinfoEncryptionEncValuesSupported;
      return this;
    }

    public OpMetadataBuilder requestObjectSigningAlgValuesSupported(
        final List<String> requestObjectSigningAlgValuesSupported) {
      this.metadata.requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported;
      return this;
    }

    public OpMetadataBuilder requestObjectEncryptionAlgValuesSupported(
        final List<String> requestObjectEncryptionAlgValuesSupported) {
      this.metadata.requestObjectEncryptionAlgValuesSupported = requestObjectEncryptionAlgValuesSupported;
      return this;
    }

    public OpMetadataBuilder requestObjectEncryptionEncValuesSupported(
        final List<String> requestObjectEncryptionEncValuesSupported) {
      this.metadata.requestObjectEncryptionEncValuesSupported = requestObjectEncryptionEncValuesSupported;
      return this;
    }

    public OpMetadataBuilder displayValuesSupported(final List<String> displayValuesSupported) {
      this.metadata.displayValuesSupported = displayValuesSupported;
      return this;
    }

    public OpMetadataBuilder claimTypesSupported(final List<String> claimTypesSupported) {
      this.metadata.claimTypesSupported = claimTypesSupported;
      return this;
    }

    public OpMetadataBuilder claimsSupported(final List<String> claimsSupported) {
      this.metadata.claimsSupported = claimsSupported;
      return this;
    }

    public OpMetadataBuilder claimsLocalesSupported(final List<String> claimsLocalesSupported) {
      this.metadata.claimsLocalesSupported = claimsLocalesSupported;
      return this;
    }

    public OpMetadataBuilder claimsParameterSupported(final Boolean claimsParameterSupported) {
      this.metadata.claimsParameterSupported = claimsParameterSupported;
      return this;
    }

    public OpMetadataBuilder requestParameterSupported(final Boolean requestParameterSupported) {
      this.metadata.requestParameterSupported = requestParameterSupported;
      return this;
    }

    public OpMetadataBuilder requestUriParameterSupported(final Boolean requestUriParameterSupported) {
      this.metadata.requestUriParameterSupported = requestUriParameterSupported;
      return this;
    }

    public OpMetadataBuilder requireRequestUriRegistration(final Boolean requireRequestUriRegistration) {
      this.metadata.requireRequestUriRegistration = requireRequestUriRegistration;
      return this;
    }

    public OpMetadataBuilder oidcSeDiscoUserMessageSupported(final Boolean oidcSeDiscoUserMessageSupported) {
      this.metadata.oidcSeDiscoUserMessageSupported = oidcSeDiscoUserMessageSupported;
      return this;
    }

    public OpMetadataBuilder oidcSeDiscoUserMessageSupportedMimeTypes(
        final List<String> oidcSeDiscoUserMessageSupportedMimeTypes) {
      this.metadata.oidcSeDiscoUserMessageSupportedMimeTypes = oidcSeDiscoUserMessageSupportedMimeTypes;
      return this;
    }

    public OpMetadataBuilder oidcSeDiscoAuthnProviderSupported(final Boolean oidcSeDiscoAuthnProviderSupported) {
      this.metadata.oidcSeDiscoAuthnProviderSupported = oidcSeDiscoAuthnProviderSupported;
      return this;
    }

    /** {@inheritDoc} */
    @Override
    public OpMetadata build() {
      return this.metadata;
    }
  }

}
