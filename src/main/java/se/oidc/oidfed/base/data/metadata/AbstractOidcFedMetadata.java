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
import com.nimbusds.jose.jwk.JWKSet;
import lombok.Getter;
import lombok.Setter;
import se.oidc.oidfed.base.data.LanguageObject;
import se.oidc.oidfed.base.data.LanguageTaggedJson;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Abstract class for Entity metadata
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public abstract class AbstractOidcFedMetadata implements LanguageTaggedJson {

  @JsonIgnore
  private final List<String> languageParameters;

  @JsonProperty("organization_name")
  @Getter
  @Setter
  protected LanguageObject<String> organizationName;

  @JsonProperty("logo_uri")
  @Getter
  @Setter
  protected LanguageObject<String> logoUri;

  @JsonProperty("contacts")
  @Getter
  @Setter
  protected List<String> contacts;

  @JsonProperty("policy_uri")
  @Getter
  @Setter
  protected String policyUri;

  @JsonProperty("homepage_uri")
  @Getter
  @Setter
  protected String homepageUri;

  @JsonProperty("signed_jwks_uri")
  @Getter
  @Setter
  protected String signedJwksUri;

  @JsonProperty("jwks_uri")
  @Getter
  @Setter
  protected String jwksUri;

  @JsonProperty("jwks")
  protected Map<String, Object> jwkSet;

  /**
   * Constructor
   */
  public AbstractOidcFedMetadata() {
    this.languageParameters = new ArrayList<>();
    this.addLanguageParametersTags(List.of("organization_name", "logo_uri"));
  }

  /**
   * Get metadata JWK set
   *
   * @return JWK set
   * @throws ParseException error parsing JWK set data
   */
  @JsonIgnore
  public JWKSet getJwkSet() throws ParseException {
    if (this.jwkSet == null) {
      return null;
    }
    return JWKSet.parse(this.jwkSet);
  }

  /**
   * Set metadata JWK set
   *
   * @param jwkSet JWK set
   */
  @JsonIgnore
  public void setJwkSet(final JWKSet jwkSet) {
    this.jwkSet = jwkSet.toJSONObject();
  }

  /**
   * Add parameter names to language tagged parameter list. This list contains the name of all parameters that is
   * defined as a language tagged parameter
   *
   * @param additionalLanguageParameterTags parameter names to add
   */
  protected void addLanguageParametersTags(final List<String> additionalLanguageParameterTags) {
    this.languageParameters.addAll(
        Optional.ofNullable(additionalLanguageParameterTags).orElse(new ArrayList<>()).stream()
            .filter(s -> !this.languageParameters.contains(s))
            .toList()
    );
  }

  /**
   * Get the language tagged parameters for this metadata type
   *
   * @return language tagged parameter names
   */
  @JsonIgnore
  @Override
  public List<String> getLanguageTaggedParameters() {
    return this.languageParameters;
  }

  /**
   * Converts this metadata object to a JSON string
   *
   * @param prettyPrinting set to true to get formatted JSON output
   * @return JSON string representing this metadata object
   * @throws JsonProcessingException error processing metadata to JSON
   */
  abstract public String toJson(boolean prettyPrinting) throws JsonProcessingException;

  /**
   * Converts this metadata object to a JSON object
   *
   * @return metadata JSON object
   * @throws JsonProcessingException error parsing metadata to a JSON object
   */
  abstract public Map<String, Object> toJsonObject() throws JsonProcessingException;

  /**
   * Builder for this metadata object
   *
   * @param <T> Type of metadata
   * @param <B> Type of builder
   */
  protected static abstract class AbstractOidcFedMetadataBuilder<T extends AbstractOidcFedMetadata,
      B extends AbstractOidcFedMetadataBuilder<?, ?>> {

    /** The metadata object to build */
    protected T metadata;

    /**
     * Constructor
     *
     * @param metadata empty metadata object to populate with values by this builder
     */
    public AbstractOidcFedMetadataBuilder(final T metadata) {
      this.metadata = metadata;
    }

    public B organizationName(final LanguageObject<String> organizationName) {
      this.metadata.organizationName = organizationName;
      return this.getReturnedBuilderInstance();
    }

    public B logoUri(final LanguageObject<String> logoUri) {
      this.metadata.logoUri = logoUri;
      return this.getReturnedBuilderInstance();
    }

    public B contacts(final List<String> contacts) {
      this.metadata.contacts = contacts;
      return this.getReturnedBuilderInstance();
    }

    public B policyUri(final String policyUri) {
      this.metadata.policyUri = policyUri;
      return this.getReturnedBuilderInstance();
    }

    public B homepageUri(final String homepageUri) {
      this.metadata.homepageUri = homepageUri;
      return this.getReturnedBuilderInstance();
    }

    public B signedJwksUri(final String signedJwksUri) {
      this.metadata.signedJwksUri = signedJwksUri;
      return this.getReturnedBuilderInstance();
    }

    public B jwksUri(final String jwksUri) {
      this.metadata.jwksUri = jwksUri;
      return this.getReturnedBuilderInstance();
    }

    public B jwkSet(final JWKSet jwkSet) {
      this.metadata.jwkSet = jwkSet.toJSONObject();
      return this.getReturnedBuilderInstance();
    }

    /**
     * Get the instance of the builder that is returned after each parameter setting. This specifies which builder to
     * return when the builder is used for cascading input:
     * <code>
     * builder .parameter1(value1) .parameter2(value2) .build();
     * </code>
     * This is normally implemented by a "return this;" where "this" is the extending building class.
     *
     * @return the builder instance to return for cascading
     */
    abstract B getReturnedBuilderInstance();

    /**
     * Build metadata
     *
     * @return metadata
     */
    protected abstract T build();
  }

}
