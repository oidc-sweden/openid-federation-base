package se.swedenconnect.oidcfed.commons.data.metadata;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.oidcfed.commons.data.OidcLangJsonSerializer;

/**
 * Oauth client metadata
 */
public class ClientMetadata extends BasicClientMetadata {

  @JsonIgnore
  @Getter private static final OidcLangJsonSerializer<ClientMetadata> jsonSerializer =
    new OidcLangJsonSerializer<>(ClientMetadata.class);

  /**
   * String containing a space-separated list of scope values (as
   * described in Section 3.3 of OAuth 2.0 [RFC6749]) that the client
   * can use when requesting access tokens.  The semantics of values in
   * this list are service specific.  If omitted, an authorization
   * server MAY register a client with a default set of scopes.
   */
  @JsonProperty("scope")
  @Getter @Setter private String scope;

  /**
   * A unique identifier string (e.g., a Universally Unique Identifier
   * (UUID)) assigned by the client developer or software publisher
   * used by registration endpoints to identify the client software to
   * be dynamically registered.
   */
  @JsonProperty("software_id")
  @Getter @Setter private String softwareId;

  /**
   * A version identifier string for the client software identified by "software_id".
   */
  @JsonProperty("software_version")
  @Getter @Setter private String softwareVersion;

  /**
   * Constructor
   */
  public ClientMetadata() {
    addLanguageParametersTags(List.of());
  }

  /** {@inheritDoc} */
  @Override public String toJson(boolean prettyPrinting) throws JsonProcessingException {
    return jsonSerializer.setPrettyPrinting(prettyPrinting).toJson(this);
  }

  /** {@inheritDoc} */
  @Override public Map<String, Object> toJsonObject() throws JsonProcessingException {
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

    @Override ClientMetadataBuilder getReturnedBuilderInstance() {
      return this;
    }

    public ClientMetadataBuilder scope(String scope){
      this.metadata.scope = scope;
      return this;
    }
    public ClientMetadataBuilder softwareId(String softwareId){
      this.metadata.softwareId = softwareId;
      return this;
    }
    public ClientMetadataBuilder softwareVersion(String softwareVersion){
      this.metadata.softwareVersion = softwareVersion;
      return this;
    }

    @Override public ClientMetadata build() {
      return metadata;
    }
  }


}
