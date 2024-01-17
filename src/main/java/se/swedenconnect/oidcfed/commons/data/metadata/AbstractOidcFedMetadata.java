package se.swedenconnect.oidcfed.commons.data.metadata;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.jwk.JWKSet;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.oidcfed.commons.data.LanguageObject;
import se.swedenconnect.oidcfed.commons.data.LanguageTaggedJson;

/**
 * Abstract class for Entity metadata
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public abstract class AbstractOidcFedMetadata implements LanguageTaggedJson {

  @JsonIgnore
  private final List<String> languageParameters;

  @JsonProperty("organization_name")
  @Getter @Setter protected LanguageObject<String> organizationName;

  @JsonProperty("logo_uri")
  @Getter @Setter protected LanguageObject<String> logoUri;

  @JsonProperty("contacts")
  @Getter @Setter protected List<String> contacts;

  @JsonProperty("policy_uri")
  @Getter @Setter protected String policyUri;

  @JsonProperty("homepage_uri")
  @Getter @Setter protected String homepageUri;

  @JsonProperty("signed_jwks_uri")
  @Getter @Setter protected String signedJwksUri;

  @JsonProperty("jwks_uri")
  @Getter @Setter protected String jwksUri;

  @JsonProperty("jwks")
  protected Map<String, Object> jwkSet;

  /**
   * Constructor
   */
  public AbstractOidcFedMetadata() {
    languageParameters = new ArrayList<>();
    addLanguageParametersTags(List.of("organization_name", "logo_uri"));
  }

  /**
   * Get metadata JWK set
   *
   * @return JWK set
   * @throws ParseException error parsing JWK set data
   */
  @JsonIgnore
  public JWKSet getJwkSet() throws ParseException {
    if (jwkSet == null){
      return null;
    }
    return JWKSet.parse(this.jwkSet);
  }

  /**
   * Set metadata JWK set
   * @param jwkSet JWK set
   */
  @JsonIgnore
  public void setJwkSet(JWKSet jwkSet) {
    this.jwkSet = jwkSet.toJSONObject();
  }

  /**
   * Add parameter names to language tagged parameter list. This list contains the name of all
   * parameters that is defined as a language tagged parameter
   *
   * @param additionalLanguageParameterTags parameter names to add
   */
  protected void addLanguageParametersTags(List<String> additionalLanguageParameterTags) {
    languageParameters.addAll(
      Optional.ofNullable(additionalLanguageParameterTags).orElse(new ArrayList<>()).stream()
        .filter(s -> !languageParameters.contains(s))
        .toList()
    );
  }

  /**
   * Get the language tagged parameters for this metadata type
   * @return language tagged parameter names
   */
  @JsonIgnore
  @Override public List<String> getLanguageTaggedParameters() {
    return languageParameters;
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
    B extends AbstractOidcFedMetadataBuilder<?,?>> {

    /** The metadata object to build */
    protected T metadata;

    /**
     * Constructor
     *
     * @param metadata empty metadata object to populate with values by this builder
     */
    public AbstractOidcFedMetadataBuilder(T metadata) {
      this.metadata = metadata;
    }

    public B organizationName(LanguageObject<String> organizationName){
      this.metadata.organizationName = organizationName;
      return getReturnedBuilderInstance();
    }
    public B logoUri(LanguageObject<String> logoUri) {
      this.metadata.logoUri = logoUri;
      return getReturnedBuilderInstance();
    }
    public B contacts(List<String> contacts){
      this.metadata.contacts = contacts;
      return getReturnedBuilderInstance();
    }
    public B policyUri(String policyUri){
      this.metadata.policyUri = policyUri;
      return getReturnedBuilderInstance();
    }
    public B homepageUri(String homepageUri){
      this.metadata.homepageUri = homepageUri;
      return getReturnedBuilderInstance();
    }
    public B signedJwksUri(String signedJwksUri){
      this.metadata.signedJwksUri = signedJwksUri;
      return getReturnedBuilderInstance();
    }
    public B jwksUri(String jwksUri) {
      this.metadata.jwksUri = jwksUri;
      return getReturnedBuilderInstance();
    }
    public B jwkSet(JWKSet jwkSet){
      this.metadata.jwkSet = jwkSet.toJSONObject();
      return getReturnedBuilderInstance();
    }

    /**
     * Get the instance of the builder that is returned after each parameter setting.
     * This specifies which builder to return when the builder is used for cascading input:
     *  <code>
     *    builder
     *      .parameter1(value1)
     *      .parameter2(value2)
     *      .build();
     *  </code>
     *  This is normally implemented by a "return this;" where "this" is the extending building class.
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
