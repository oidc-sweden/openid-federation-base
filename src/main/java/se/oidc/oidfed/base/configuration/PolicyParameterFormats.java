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
package se.oidc.oidfed.base.configuration;

import se.oidc.oidfed.base.process.metadata.PolicyTranslationException;

import java.util.Arrays;

/**
 * Enumeration of supported policy parameters
 */
public enum PolicyParameterFormats {

  // Generic metadata parameters
  organization_name(null, ValueType.STRING),
  logo_uri(null, ValueType.STRING),
  contacts(null, ValueType.STRING_ARRAY),
  policy_uri(null, ValueType.STRING),
  homepage_uri(null, ValueType.STRING),
  signed_jwks_uri(null, ValueType.STRING),
  jwks_uri(null, ValueType.STRING),

  // Common AS/OP metadata
  issuer(null, ValueType.STRING),
  authorization_endpoint(null, ValueType.STRING),
  token_endpoint(null, ValueType.STRING),
  registration_endpoint(null, ValueType.STRING),
  scopes_supported(null, ValueType.STRING_ARRAY),
  response_types_supported(null, ValueType.STRING_ARRAY),
  response_modes_supported(null, ValueType.STRING_ARRAY),
  grant_types_supported(null, ValueType.STRING_ARRAY),
  token_endpoint_auth_methods_supported(null, ValueType.STRING_ARRAY),
  token_endpoint_auth_signing_alg_values_supported(null, ValueType.STRING_ARRAY),
  service_documentation(null, ValueType.STRING),
  ui_locales_supported(null, ValueType.STRING_ARRAY),
  op_policy_uri(null, ValueType.STRING),
  op_tos_uri(null, ValueType.STRING),
  introspection_endpoint(null, ValueType.STRING),
  introspection_endpoint_auth_methods_supported(null, ValueType.STRING_ARRAY),
  introspection_endpoint_auth_signing_alg_values_supported(null, ValueType.STRING_ARRAY),
  code_challenge_methods_supported(null, ValueType.STRING_ARRAY),

  // OpenID Federation metadata
  client_registration_types_supported(null, ValueType.STRING_ARRAY),
  federation_registration_endpoint(null, ValueType.STRING),
  request_authentication_methods_supported(null, ValueType.OBJECT),
  request_authentication_signing_alg_values_supported(null, ValueType.STRING_ARRAY),

  // Additional Op metadata
  userinfo_endpoint(null, ValueType.STRING),
  acr_values_supported(null, ValueType.STRING_ARRAY),
  subject_types_supported(null, ValueType.STRING_ARRAY),
  id_token_signing_alg_values_supported(null, ValueType.STRING_ARRAY),
  id_token_encryption_alg_values_supported(null, ValueType.STRING_ARRAY),
  id_token_encryption_enc_values_supported(null, ValueType.STRING_ARRAY),
  userinfo_signing_alg_values_supported(null, ValueType.STRING_ARRAY),
  userinfo_encryption_alg_values_supported(null, ValueType.STRING_ARRAY),
  userinfo_encryption_enc_values_supported(null, ValueType.STRING_ARRAY),
  request_object_signing_alg_values_supported(null, ValueType.STRING_ARRAY),
  request_object_encryption_alg_values_supported(null, ValueType.STRING_ARRAY),
  request_object_encryption_enc_values_supported(null, ValueType.STRING_ARRAY),
  display_values_supported(null, ValueType.STRING_ARRAY),
  claim_types_supported(null, ValueType.STRING_ARRAY),
  claims_supported(null, ValueType.STRING_ARRAY),
  claims_locales_supported(null, ValueType.STRING_ARRAY),
  claims_parameter_supported(null, ValueType.BOOLEAN),
  request_parameter_supported(null, ValueType.BOOLEAN),
  request_uri_parameter_supported(null, ValueType.BOOLEAN),
  require_request_uri_registration(null, ValueType.BOOLEAN),
  oidcSeDiscoUserMessageSupported("https://id.oidc.se/disco/userMessageSupported", ValueType.BOOLEAN),
  oidcSeDiscoUserMessageSupportedMimeTypes("https://id.oidc.se/disco/userMessageSupportedMimeTypes",
      ValueType.STRING_ARRAY),
  oidcSeDiscoAuthnProviderSupported("https://id.oidc.se/disco/authnProviderSupported", ValueType.BOOLEAN),

  // Additional Authorization server metadata
  revocation_endpoint(null, ValueType.STRING),
  revocation_endpoint_auth_methods_supported(null, ValueType.STRING_ARRAY),
  revocation_endpoint_auth_signing_alg_values_supported(null, ValueType.STRING_ARRAY),

  // Common Client/RP metadata
  redirect_uris(null, ValueType.STRING_ARRAY),
  token_endpoint_auth_method(null, ValueType.STRING),
  grant_types(null, ValueType.STRING_ARRAY),
  response_types(null, ValueType.STRING_ARRAY),
  client_name(null, ValueType.STRING),
  client_uri(null, ValueType.STRING),
  tos_uri(null, ValueType.STRING),

  // Additional OAuth Client metadata
  scope(null, ValueType.SPACE_SEPARATED_STRINGS),
  software_id(null, ValueType.STRING),
  software_version(null, ValueType.STRING),

  // Additional OIDC RP metadata
  application_type(null, ValueType.STRING),
  sector_identifier_uri(null, ValueType.STRING),
  subject_type(null, ValueType.STRING),
  id_token_signed_response_alg(null, ValueType.STRING),
  id_token_encrypted_response_alg(null, ValueType.STRING),
  userinfo_signed_response_alg(null, ValueType.STRING),
  userinfo_encrypted_response_alg(null, ValueType.STRING),
  userinfo_encrypted_response_enc(null, ValueType.STRING),
  request_object_signing_alg(null, ValueType.STRING),
  request_object_encryption_alg(null, ValueType.STRING),
  request_object_encryption_enc(null, ValueType.STRING),
  token_endpoint_auth_signing_alg(null, ValueType.STRING),
  default_max_age(null, ValueType.INTEGER),
  require_auth_time(null, ValueType.BOOLEAN),
  default_acr_values(null, ValueType.STRING_ARRAY),
  initiate_login_uri(null, ValueType.STRING),
  request_uris(null, ValueType.STRING),

  // Federation endpoint metadata
  federation_fetch_endpoint(null, ValueType.STRING),
  federation_list_endpoint(null, ValueType.STRING),
  federation_resolve_endpoint(null, ValueType.STRING),
  federation_trust_mark_status_endpoint(null, ValueType.STRING),
  federation_trust_mark_list_endpoint(null, ValueType.STRING),
  federation_trust_mark_endpoint(null, ValueType.STRING),
  federation_historical_keys_endpoint(null, ValueType.STRING),
  federation_discovery_endpoint(null, ValueType.STRING);

  final String alternateParameterName;

  private final String valueType;

  PolicyParameterFormats(final String alternateParameterName, final String valueType) {
    this.alternateParameterName = alternateParameterName;
    this.valueType = valueType;
  }

  public String getValueType() {
    return this.valueType;
  }

  public String getParameterName() {
    if (this.alternateParameterName == null) {
      return this.name();
    }
    return this.alternateParameterName;
  }

  /**
   * Get the value type for a supported parameter name
   *
   * @param parameterName the parameter name
   * @return value type
   * @throws PolicyTranslationException if no such parameter name is supported
   */
  public static String getValueType(final String parameterName) throws PolicyTranslationException {
    return Arrays.stream(values())
        .filter(policyParameter -> policyParameter.getParameterName().equals(parameterName))
        .map(PolicyParameterFormats::getValueType)
        .findFirst()
        .orElseThrow(() -> new PolicyTranslationException(
            "No such policy parameter is supported for metadata policy processing"));
  }

  public MetadataParameter toMetadataParameter() {
    final String parameterName = this.getParameterName();
    try {
      return new MetadataParameter(parameterName, getValueType(parameterName));
    }
    catch (final PolicyTranslationException e) {
      throw new RuntimeException(e);
    }
  }

}
