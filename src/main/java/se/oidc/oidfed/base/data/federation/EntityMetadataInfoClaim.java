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
package se.oidc.oidfed.base.data.federation;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import lombok.Data;
import lombok.Getter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Metadata claims data for both the metadata claim and the metadata_policy claim
 */
@Getter
@JsonSerialize(using = EntityMetadataInfoClaim.EntityMetadataInfoClaimSerializer.class)
@JsonDeserialize(using = EntityMetadataInfoClaim.EntityMetadataInfoClaimDeserializer.class)
public class EntityMetadataInfoClaim {

  public static final String OPENID_RELYING_PARTY = "openid_relying_party";
  public static final String OPENID_PROVIDER = "openid_provider";
  public static final String OAUTH_AUTHORIZATION_SERVER = "oauth_authorization_server";
  public static final String OAUTH_CLIENT = "oauth_client";
  public static final String OAUTH_RESOURCE = "oauth_resource";
  public static final String FEDERATION_ENTITY = "federation_entity";

  protected Map<String, Map<String, Object>> claimObjects;

  /**
   * Constructor for the EntityMetadataInfoClaim class.
   */
  protected EntityMetadataInfoClaim() {
    claimObjects = new HashMap<>();
  }

  /*
   * Backwards compatible getters and setters for common metadata types;
   */

  /**
   * Retrieves the OIDC Relying Party metadata object.
   *
   * @return Relying Party metadata JSON object map
   */
  public Map<String, Object> getOidcRelyingPartyMetadataObject() {
    return claimObjects.get(OPENID_RELYING_PARTY);
  }

  /**
   * Sets the OIDC relying party metadata object.
   *
   * @param oidcRelyingPartyMetadata a JSON object map representing the OIDC relying party metadata
   */
  public void setOidcRelyingPartyMetadataObject(Map<String, Object> oidcRelyingPartyMetadata){
    this.claimObjects.put(OPENID_RELYING_PARTY, oidcRelyingPartyMetadata);

  }

  /**
   * Retrieves the OpenID Connect Provider metadata as a JSON object map.
   *
   * @return OpenID Provider metadata JSON object map
   */
  public Map<String, Object> getOpMetadataObject(){
    return claimObjects.get(OPENID_PROVIDER);
  }

  /**
   * Sets the OpenID Connect metadata object for the specific OpenID Provider.
   *
   * @param opMetadata a JSON object map representing the OpenID Provider metadata
   */
  public void setOpMetadataObject(Map<String, Object> opMetadata){
    this.claimObjects.put(OPENID_PROVIDER, opMetadata);
  }

  /**
   * Retrieves the authorization server metadata JSON object map.
   *
   * @return authorization server metadata JSON object map.
   */
  public Map<String, Object> getAuthorizationServerMetadataObject(){
    return claimObjects.get(OAUTH_AUTHORIZATION_SERVER);
  }

  /**
   * Sets the authorization server metadata JSON object map.
   *
   * @param authorizationServerMetadata authorization server metadata JSON object map
   */
  public void setAuthorizationServerMetadataObject(Map<String, Object> authorizationServerMetadata){
    this.claimObjects.put(OAUTH_AUTHORIZATION_SERVER, authorizationServerMetadata);
  }

  /**
   * Retrieves the OAuth client metadata JSON object map.
   *
   * @return OAuth client metadata JSON object map
   */
  public Map<String, Object> getOauthClientMetadataObject(){
    return claimObjects.get(OAUTH_CLIENT);
  }

  /**
   * Sets the OAuth client metadata JSON object map.
   *
   * @param oauthClientMetadata OAuth client metadata JSON object map
   */
  public void setOauthClientMetadataObject(Map<String, Object> oauthClientMetadata){
    this.claimObjects.put(OAUTH_CLIENT, oauthClientMetadata);
  }

  /**
   * Retrieves the OAuth resource metadata JSON object map.
   *
   * @return OAuth resource metadata JSON object map
   */
  public Map<String, Object> getOauthResourceMetadataObject(){
    return claimObjects.get(OAUTH_RESOURCE);
  }

  /**
   * Set the OAuth resource metadata JSON object map.
   *
   * @param oauthResourceMetadata OAuth resource metadata JSON object map
   */
  public void setOauthResourceMetadataObject(Map<String, Object> oauthResourceMetadata){
    this.claimObjects.put(OAUTH_RESOURCE, oauthResourceMetadata);
  }

  /**
   * Retrieves the metadata JSON object map for the federation entity.
   *
   * @return federation entity JSON object map
   */
  public Map<String, Object> getFederationEntityMetadataObject(){
    return claimObjects.get(FEDERATION_ENTITY);
  }

  /**
   * Sets the metadata JSON object map for the federation entity.
   *
   * @param federationEntityMetadata federation entity JSON object map
   */
  public void setFederationEntityMetadataObject(Map<String, Object> federationEntityMetadata){
    this.claimObjects.put(FEDERATION_ENTITY, federationEntityMetadata);
  }

  /**
   * Retrieves the metadata JSON object map for the specified metadata type.
   *
   * @param metadataTypeName the type of metadata for which to retrieve the JSON object map
   * @return a JSON object map representing the metadata object, or null if the specified type is not found.
   */
  public Map<String, Object> getMetadataClaimsObject(String metadataTypeName) {
    return claimObjects.get(metadataTypeName);
  }

  /**
   * Sets the metadata claims object for the specified metadata type.
   *
   * @param metadataTypeName the type of metadata for which to set the JSON object map
   * @param metadataClaims a JSON object map representing the metadata claims
   */
  public void setMetadataClaimsObject(String metadataTypeName, Map<String, Object> metadataClaims) {
    this.claimObjects.put(metadataTypeName, metadataClaims);
  }

  /**
   * Constructs a new EntityMetadataInfoClaimBuilder for building a {@link EntityMetadataInfoClaim}.
   *
   * @return a new instance of EntityMetadataInfoClaimBuilder
   */
  public static EntityMetadataInfoClaimBuilder builder() {
    return new EntityMetadataInfoClaimBuilder();
  }

  /**
   * A builder class for constructing an EntityMetadataInfoClaim object with various metadata objects.
   */
  public static class EntityMetadataInfoClaimBuilder {

    private final EntityMetadataInfoClaim entityMetadataInfoClaim;

    private EntityMetadataInfoClaimBuilder() {
      this.entityMetadataInfoClaim = new EntityMetadataInfoClaim();
    }

    /**
     * Set the OIDC relying party metadata object.
     *
     * @param oidcRelyingPartyMetadataObject a JSON object map representing the OIDC relying party metadata
     * @return EntityMetadataInfoClaimBuilder instance for method chaining
     */
    public EntityMetadataInfoClaimBuilder oidcRelyingPartyMetadataObject(
        final Map<String, Object> oidcRelyingPartyMetadataObject) {
      this.entityMetadataInfoClaim.setOidcRelyingPartyMetadataObject(oidcRelyingPartyMetadataObject);
      return this;
    }

    /**
     * Sets the OpenID Connect metadata object for the specific OpenID Provider.
     *
     * @param opMetadataObject a JSON object map representing the OpenID Provider metadata
     * @return EntityMetadataInfoClaimBuilder instance for method chaining
     */
    public EntityMetadataInfoClaimBuilder opMetadataObject(final Map<String, Object> opMetadataObject) {
      this.entityMetadataInfoClaim.setOpMetadataObject(opMetadataObject);
      return this;
    }

    /**
     * Sets the authorization server metadata JSON object map.
     *
     * @param authorizationServerMetadataObject the JSON object map representing authorization server metadata
     * @return EntityMetadataInfoClaimBuilder instance for method chaining
     */
    public EntityMetadataInfoClaimBuilder authorizationServerMetadataObject(
        final Map<String, Object> authorizationServerMetadataObject) {
      this.entityMetadataInfoClaim.setAuthorizationServerMetadataObject(authorizationServerMetadataObject);
      return this;
    }

    /**
     * Sets the OAuth client metadata JSON object map.
     *
     * @param oauthClientMetadataObject A JSON object map representing the OAuth client metadata
     * @return EntityMetadataInfoClaimBuilder instance for method chaining
     */
    public EntityMetadataInfoClaimBuilder oauthClientMetadataObject(
        final Map<String, Object> oauthClientMetadataObject) {
      this.entityMetadataInfoClaim.setOauthClientMetadataObject(oauthClientMetadataObject);
      return this;
    }

    /**
     * Sets the OAuth resource metadata JSON object map.
     *
     * @param oauthResourceMetadataObject a JSON object map representing OAuth resource metadata
     * @return EntityMetadataInfoClaimBuilder instance for method chaining
     */
    public EntityMetadataInfoClaimBuilder oauthResourceMetadataObject(
        final Map<String, Object> oauthResourceMetadataObject) {
      this.entityMetadataInfoClaim.setOauthResourceMetadataObject(oauthResourceMetadataObject);
      return this;
    }

    /**
     * Sets the Federation Entity metadata JSON object map
     *
     * @param federationEntityMetadataObject a JSON object map representing Federation Entity metadata
     * @return EntityMetadataInfoClaimBuilder instance for method chaining
     */
    public EntityMetadataInfoClaimBuilder federationEntityMetadataObject(
        final Map<String, Object> federationEntityMetadataObject) {
      this.entityMetadataInfoClaim.setFederationEntityMetadataObject(federationEntityMetadataObject);
      return this;
    }

    /**
     * Sets a custom entity metadata object for a specific metadata type.
     *
     * @param metadataTypeName the type of metadata for which to set the custom entity metadata
     * @param entityMetadataObject a SON object map representing the custom entity metadata
     * @return an EntityMetadataInfoClaimBuilder instance for method chaining
     */
    public EntityMetadataInfoClaimBuilder customEntityMetadataObject(String metadataTypeName, Map<String, Object> entityMetadataObject) {
      this.entityMetadataInfoClaim.setMetadataClaimsObject(metadataTypeName, entityMetadataObject);
      return this;
    }

    /**
     * Builds and returns the EntityMetadataInfoClaim object that has been constructed so far.
     *
     * @return The EntityMetadataInfoClaim object representing the constructed entity metadata information.
     */
    public EntityMetadataInfoClaim build() {
      return this.entityMetadataInfoClaim;
    }

  }

  /**
   * Custom serializer for EntityMetadataInfoClaim objects.
   * This class extends the JsonSerializer class to handle serialization of EntityMetadataInfoClaim objects.
   * It overrides the serialize method to write the claimObjects property of the EntityMetadataInfoClaim object to the JsonGenerator.
   */
  public static class EntityMetadataInfoClaimSerializer extends JsonSerializer<EntityMetadataInfoClaim> {

    /**
     * Serializes the EntityMetadataInfoClaim object to JSON.
     *
     * @param value the EntityMetadataInfoClaim object to be serialized
     * @param gen the JsonGenerator used to write the JSON content
     * @param serializers the SerializerProvider for serialization
     * @throws IOException If an I/O error occurs while writing the JSON.
     */
    @Override
    public void serialize(EntityMetadataInfoClaim value, JsonGenerator gen, SerializerProvider serializers)
      throws IOException {
      gen.writeObject(value.getClaimObjects());
    }
  }

  /**
   * Custom JSON deserializer for EntityMetadataInfoClaim objects.
   * This class extends JsonDeserializer and defines the deserialize method to convert JSON data
   * into an EntityMetadataInfoClaim object.
   */
  public static class EntityMetadataInfoClaimDeserializer extends JsonDeserializer<EntityMetadataInfoClaim> {

    /**
     * Deserialize a JSON content into an EntityMetadataInfoClaim object.
     *
     * @param p JsonParser used to read JSON content.
     * @param ctxt DeserializationContext for deserialization configuration.
     * @return An EntityMetadataInfoClaim object populated with data from the JSON content.
     * @throws IOException if an I/O error occurs during deserialization.
     */
    @Override
    public EntityMetadataInfoClaim deserialize(JsonParser p, DeserializationContext ctxt)
      throws IOException {
      Map<String, Map<String, Object>> claimObjects = p.readValueAs(new TypeReference<Map<String, Map<String, Object>>>() {});
      EntityMetadataInfoClaim entityMetadataInfoClaim = new EntityMetadataInfoClaim();
      entityMetadataInfoClaim.claimObjects = claimObjects;
      return entityMetadataInfoClaim;
    }
  }
}
