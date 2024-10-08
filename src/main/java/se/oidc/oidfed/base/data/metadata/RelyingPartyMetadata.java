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
 * Relying party metadata
 */
public class RelyingPartyMetadata extends BasicClientMetadata {

  @JsonIgnore
  @Getter
  private static final OidcLangJsonSerializer<RelyingPartyMetadata> jsonSerializer =
      new OidcLangJsonSerializer<>(RelyingPartyMetadata.class);

  /**
   * OPTIONAL. Kind of the application. The default, if omitted, is web. The defined values are native or web. Web
   * Clients using the OAuth Implicit Grant Type MUST only register URLs using the https scheme as redirect_uris; they
   * MUST NOT use localhost as the hostname. Native Clients MUST only register redirect_uris using custom URI schemes or
   * URLs using the http: scheme with localhost as the hostname. Authorization Servers MAY place additional constraints
   * on Native Clients. Authorization Servers MAY reject Redirection URI values using the http scheme, other than the
   * localhost case for Native Clients. The Authorization Server MUST verify that all the registered redirect_uris
   * conform to these constraints. This prevents sharing a Client ID across different types of Clients.
   */
  @JsonProperty("application_type")
  @Getter
  @Setter
  private String applicationType;

  /**
   * OPTIONAL. URL using the https scheme to be used in calculating Pseudonymous Identifiers by the OP. The URL
   * references a file with a single JSON array of redirect_uri values. Please see Section 5. Providers that use
   * pairwise sub (subject) values SHOULD utilize the sector_identifier_uri value provided in the Subject Identifier
   * calculation for pairwise identifiers.
   */
  @JsonProperty("sector_identifier_uri")
  @Getter
  @Setter
  private String sectorIdentifierUri;

  /**
   * OPTIONAL. subject_type requested for responses to this Client. The subject_types_supported Discovery parameter
   * contains a list of the supported subject_type values for this server. Valid types include pairwise and public.
   */
  @JsonProperty("subject_type")
  @Getter
  @Setter
  private String subjectType;

  /**
   * OPTIONAL. JWS alg algorithm [JWA] REQUIRED for signing the ID Token issued to this Client. The value none MUST NOT
   * be used as the ID Token alg value unless the Client uses only Response Types that return no ID Token from the
   * Authorization Endpoint (such as when only using the Authorization Code Flow). The default, if omitted, is RS256.
   * The public key for validating the signature is provided by retrieving the JWK Set referenced by the jwks_uri
   * element from OpenID Connect Discovery 1.0 [OpenID.Discovery].
   */
  @JsonProperty("id_token_signed_response_alg")
  @Getter
  @Setter
  private String idTokenSignedResponseAlg;

  /**
   * OPTIONAL. JWE alg algorithm [JWA] REQUIRED for encrypting the ID Token issued to this Client. If this is requested,
   * the response will be signed then encrypted, with the result being a Nested JWT, as defined in [JWT]. The default,
   * if omitted, is that no encryption is performed.
   */
  @JsonProperty("id_token_encrypted_response_alg")
  @Getter
  @Setter
  private String idTokenEncryptedResponseAlg;

  /**
   * OPTIONAL. JWS alg algorithm [JWA] REQUIRED for signing UserInfo Responses. If this is specified, the response will
   * be JWT [JWT] serialized, and signed using JWS. The default, if omitted, is for the UserInfo Response to return the
   * Claims as a UTF-8 encoded JSON object using the application/json content-type.
   */
  @JsonProperty("userinfo_signed_response_alg")
  @Getter
  @Setter
  private String userinfoSignedResponseAlg;

  /**
   * OPTIONAL. JWE [JWE] alg algorithm [JWA] REQUIRED for encrypting UserInfo Responses. If both signing and encryption
   * are requested, the response will be signed then encrypted, with the result being a Nested JWT, as defined in [JWT].
   * The default, if omitted, is that no encryption is performed.
   */
  @JsonProperty("userinfo_encrypted_response_alg")
  @Getter
  @Setter
  private String userinfoEncryptedResponseAlg;

  /**
   * OPTIONAL. JWE enc algorithm [JWA] REQUIRED for encrypting UserInfo Responses. If userinfo_encrypted_response_alg is
   * specified, the default for this value is A128CBC-HS256. When userinfo_encrypted_response_enc is included,
   * userinfo_encrypted_response_alg MUST also be provided.
   */
  @JsonProperty("userinfo_encrypted_response_enc")
  @Getter
  @Setter
  private String userinfoEncryptedResponseEnc;

  /**
   * OPTIONAL. JWS [JWS] alg algorithm [JWA] that MUST be used for signing Request Objects sent to the OP. All Request
   * Objects from this Client MUST be rejected, if not signed with this algorithm. Request Objects are described in
   * Section 6.1 of OpenID Connect Core 1.0 [OpenID.Core]. This algorithm MUST be used both when the Request Object is
   * passed by value (using the request parameter) and when it is passed by reference (using the request_uri parameter).
   * Servers SHOULD support RS256. The value none MAY be used. The default, if omitted, is that any algorithm supported
   * by the OP and the RP MAY be used.
   */
  @JsonProperty("request_object_signing_alg")
  @Getter
  @Setter
  private String requestObjectSigningAlg;

  /**
   * OPTIONAL. JWE [JWE] alg algorithm [JWA] the RP is declaring that it may use for encrypting Request Objects sent to
   * the OP. This parameter SHOULD be included when symmetric encryption will be used, since this signals to the OP that
   * a client_secret value needs to be returned from which the symmetric key will be derived, that might not otherwise
   * be returned. The RP MAY still use other supported encryption algorithms or send unencrypted Request Objects, even
   * when this parameter is present. If both signing and encryption are requested, the Request Object will be signed
   * then encrypted, with the result being a Nested JWT, as defined in [JWT]. The default, if omitted, is that the RP is
   * not declaring whether it might encrypt any Request Objects.
   */
  @JsonProperty("request_object_encryption_alg")
  @Getter
  @Setter
  private String requestObjectEncryptionAlg;

  /**
   * OPTIONAL. JWE enc algorithm [JWA] the RP is declaring that it may use for encrypting Request Objects sent to the
   * OP. If request_object_encryption_alg is specified, the default for this value is A128CBC-HS256. When
   * request_object_encryption_enc is included, request_object_encryption_alg MUST also be provided.
   */
  @JsonProperty("request_object_encryption_enc")
  @Getter
  @Setter
  private String requestObjectEncryptionEnc;

  /**
   * OPTIONAL. JWS [JWS] alg algorithm [JWA] that MUST be used for signing the JWT [JWT] used to authenticate the Client
   * at the Token Endpoint for the private_key_jwt and client_secret_jwt authentication methods. All Token Requests
   * using these authentication methods from this Client MUST be rejected, if the JWT is not signed with this algorithm.
   * Servers SHOULD support RS256. The value none MUST NOT be used. The default, if omitted, is that any algorithm
   * supported by the OP and the RP MAY be used.
   */
  @JsonProperty("token_endpoint_auth_signing_alg")
  @Getter
  @Setter
  private String tokenEndpointAuthSigningAlg;

  /**
   * OPTIONAL. Default Maximum Authentication Age. Specifies that the End-User MUST be actively authenticated if the
   * End-User was authenticated longer ago than the specified number of seconds. The max_age request parameter overrides
   * this default value. If omitted, no default Maximum Authentication Age is specified.
   */
  @JsonProperty("default_max_age")
  @Getter
  @Setter
  private Integer defaultMaxAge;

  /**
   * OPTIONAL. Boolean value specifying whether the auth_time Claim in the ID Token is REQUIRED. It is REQUIRED when the
   * value is true. (If this is false, the auth_time Claim can still be dynamically requested as an individual Claim for
   * the ID Token using the claims request parameter described in Section 5.5.1 of OpenID Connect Core 1.0
   * [OpenID.Core].) If omitted, the default value is false.
   */
  @JsonProperty("require_auth_time")
  @Getter
  @Setter
  private Boolean requireAuthTime;

  /**
   * OPTIONAL. Default requested Authentication Context Class Reference values. Array of strings that specifies the
   * default acr values that the OP is being requested to use for processing requests from this Client, with the values
   * appearing in order of preference. The Authentication Context Class satisfied by the authentication performed is
   * returned as the acr Claim Value in the issued ID Token. The acr Claim is requested as a Voluntary Claim by this
   * parameter. The acr_values_supported discovery element contains a list of the supported acr values supported by this
   * server. Values specified in the acr_values request parameter or an individual acr Claim request override these
   * default values.
   */
  @JsonProperty("default_acr_values")
  @Getter
  @Setter
  private List<String> defaultAcrValues;

  /**
   * OPTIONAL. URI using the https scheme that a third party can use to initiate a login by the RP, as specified in
   * Section 4 of OpenID Connect Core 1.0 [OpenID.Core]. The URI MUST accept requests via both GET and POST. The Client
   * MUST understand the login_hint and iss parameters and SHOULD support the target_link_uri parameter.
   */
  @JsonProperty("initiate_login_uri")
  @Getter
  @Setter
  private String initiateLoginUri;

  /**
   * OPTIONAL. Array of request_uri values that are pre-registered by the RP for use at the OP. Servers MAY cache the
   * contents of the files referenced by these URIs and not retrieve them at the time they are used in a request. OPs
   * can require that request_uri values used be pre-registered with the require_request_uri_registration discovery
   * parameter.
   */
  @JsonProperty("request_uris")
  @Getter
  @Setter
  private String requestUris;

  /**
   * Constructor
   */
  public RelyingPartyMetadata() {
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
   * Get builder for relying party metadata
   *
   * @return builder
   */
  public static RelyingPartyMetadataBuilder builder() {
    return new RelyingPartyMetadataBuilder();
  }

  /**
   * Builder class for RP metadata
   */
  public static class RelyingPartyMetadataBuilder
      extends BasicClientMetadataBuilder<RelyingPartyMetadata, RelyingPartyMetadataBuilder> {

    /**
     * Private constructor
     */
    private RelyingPartyMetadataBuilder() {
      super(new RelyingPartyMetadata());
    }

    /** {@inheritDoc} */
    @Override
    RelyingPartyMetadataBuilder getReturnedBuilderInstance() {
      return this;
    }

    public RelyingPartyMetadataBuilder applicationType(final String applicationType) {
      this.metadata.applicationType = applicationType;
      return this;
    }

    public RelyingPartyMetadataBuilder sectorIdentifierUri(final String sectorIdentifierUri) {
      this.metadata.sectorIdentifierUri = sectorIdentifierUri;
      return this;
    }

    public RelyingPartyMetadataBuilder subjectType(final String subjectType) {
      this.metadata.subjectType = subjectType;
      return this;
    }

    public RelyingPartyMetadataBuilder idTokenSignedResponseAlg(final String idTokenSignedResponseAlg) {
      this.metadata.idTokenSignedResponseAlg = idTokenSignedResponseAlg;
      return this;
    }

    public RelyingPartyMetadataBuilder idTokenEncryptedResponseAlg(final String idTokenEncryptedResponseAlg) {
      this.metadata.idTokenEncryptedResponseAlg = idTokenEncryptedResponseAlg;
      return this;
    }

    public RelyingPartyMetadataBuilder userinfoSignedResponseAlg(final String userinfoSignedResponseAlg) {
      this.metadata.userinfoSignedResponseAlg = userinfoSignedResponseAlg;
      return this;
    }

    public RelyingPartyMetadataBuilder userinfoEncryptedResponseAlg(final String userinfoEncryptedResponseAlg) {
      this.metadata.userinfoEncryptedResponseAlg = userinfoEncryptedResponseAlg;
      return this;
    }

    public RelyingPartyMetadataBuilder userinfoEncryptedResponseEnc(final String userinfoEncryptedResponseEnc) {
      this.metadata.userinfoEncryptedResponseEnc = userinfoEncryptedResponseEnc;
      return this;
    }

    public RelyingPartyMetadataBuilder requestObjectSigningAlg(final String requestObjectSigningAlg) {
      this.metadata.requestObjectSigningAlg = requestObjectSigningAlg;
      return this;
    }

    public RelyingPartyMetadataBuilder requestObjectEncryptionAlg(final String requestObjectEncryptionAlg) {
      this.metadata.requestObjectEncryptionAlg = requestObjectEncryptionAlg;
      return this;
    }

    public RelyingPartyMetadataBuilder requestObjectEncryptionEnc(final String requestObjectEncryptionEnc) {
      this.metadata.requestObjectEncryptionEnc = requestObjectEncryptionEnc;
      return this;
    }

    public RelyingPartyMetadataBuilder tokenEndpointAuthSigningAlg(final String tokenEndpointAuthSigningAlg) {
      this.metadata.tokenEndpointAuthSigningAlg = tokenEndpointAuthSigningAlg;
      return this;
    }

    public RelyingPartyMetadataBuilder defaultMaxAge(final Integer defaultMaxAge) {
      this.metadata.defaultMaxAge = defaultMaxAge;
      return this;
    }

    public RelyingPartyMetadataBuilder requireAuthTime(final Boolean requireAuthTime) {
      this.metadata.requireAuthTime = requireAuthTime;
      return this;
    }

    public RelyingPartyMetadataBuilder defaultAcrValues(final List<String> defaultAcrValues) {
      this.metadata.defaultAcrValues = defaultAcrValues;
      return this;
    }

    public RelyingPartyMetadataBuilder initiateLoginUri(final String initiateLoginUri) {
      this.metadata.initiateLoginUri = initiateLoginUri;
      return this;
    }

    public RelyingPartyMetadataBuilder requestUris(final String requestUris) {
      this.metadata.requestUris = requestUris;
      return this;
    }

    /** {@inheritDoc} */
    @Override
    public RelyingPartyMetadata build() {
      return this.metadata;
    }
  }
}
