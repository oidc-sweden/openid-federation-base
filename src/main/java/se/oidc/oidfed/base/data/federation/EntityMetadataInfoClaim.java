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

  protected EntityMetadataInfoClaim() {
    claimObjects = new HashMap<>();
  }

  /*
   * Backwards compatible getters and setters for common metadata types;
   */
  public Map<String, Object> getOidcRelyingPartyMetadataObject() {
    return claimObjects.get(OPENID_RELYING_PARTY);
  }

  public void setOidcRelyingPartyMetadataObject(Map<String, Object> oidcRelyingPartyMetadata){
    this.claimObjects.put(OPENID_RELYING_PARTY, oidcRelyingPartyMetadata);

  }

  public Map<String, Object> getOpMetadataObject(){
    return claimObjects.get(OPENID_PROVIDER);
  }

  public void setOpMetadataObject(Map<String, Object> opMetadata){
    this.claimObjects.put(OPENID_PROVIDER, opMetadata);
  }

  public Map<String, Object> getAuthorizationServerMetadataObject(){
    return claimObjects.get(OAUTH_AUTHORIZATION_SERVER);
  }

  public void setAuthorizationServerMetadataObject(Map<String, Object> authorizationServerMetadata){
    this.claimObjects.put(OAUTH_AUTHORIZATION_SERVER, authorizationServerMetadata);
  }

  public Map<String, Object> getOauthClientMetadataObject(){
    return claimObjects.get(OAUTH_CLIENT);
  }

  public void setOauthClientMetadataObject(Map<String, Object> oauthClientMetadata){
    this.claimObjects.put(OAUTH_CLIENT, oauthClientMetadata);
  }

  public Map<String, Object> getOauthResourceMetadataObject(){
    return claimObjects.get(OAUTH_RESOURCE);
  }

  public void setOauthResourceMetadataObject(Map<String, Object> oauthResourceMetadata){
    this.claimObjects.put(OAUTH_RESOURCE, oauthResourceMetadata);
  }

  public Map<String, Object> getFederationEntityMetadataObject(){
    return claimObjects.get(FEDERATION_ENTITY);
  }

  public void setFederationEntityMetadataObject(Map<String, Object> federationEntityMetadata){
    this.claimObjects.put(FEDERATION_ENTITY, federationEntityMetadata);
  }

  public Map<String, Object> getMetadataClaimsObject(String metadataTypeName) {
    return claimObjects.get(metadataTypeName);
  }

  public void setMetadataClaimsObject(String metadataTypeName, Map<String, Object> metadataClaims) {
    this.claimObjects.put(metadataTypeName, metadataClaims);
  }

  public static EntityMetadataInfoClaimBuilder builder() {
    return new EntityMetadataInfoClaimBuilder();
  }

  public static class EntityMetadataInfoClaimBuilder {

    private final EntityMetadataInfoClaim entityMetadataInfoClaim;

    private EntityMetadataInfoClaimBuilder() {
      this.entityMetadataInfoClaim = new EntityMetadataInfoClaim();
    }

    public EntityMetadataInfoClaimBuilder oidcRelyingPartyMetadataObject(
        final Map<String, Object> oidcRelyingPartyMetadataObject) {
      this.entityMetadataInfoClaim.setOidcRelyingPartyMetadataObject(oidcRelyingPartyMetadataObject);
      return this;
    }

    public EntityMetadataInfoClaimBuilder opMetadataObject(final Map<String, Object> opMetadataObject) {
      this.entityMetadataInfoClaim.setOpMetadataObject(opMetadataObject);
      return this;
    }

    public EntityMetadataInfoClaimBuilder authorizationServerMetadataObject(
        final Map<String, Object> authorizationServerMetadataObject) {
      this.entityMetadataInfoClaim.setAuthorizationServerMetadataObject(authorizationServerMetadataObject);
      return this;
    }

    public EntityMetadataInfoClaimBuilder oauthClientMetadataObject(
        final Map<String, Object> oauthClientMetadataObject) {
      this.entityMetadataInfoClaim.setOauthClientMetadataObject(oauthClientMetadataObject);
      return this;
    }

    public EntityMetadataInfoClaimBuilder oauthResourceMetadataObject(
        final Map<String, Object> oauthResourceMetadataObject) {
      this.entityMetadataInfoClaim.setOauthResourceMetadataObject(oauthResourceMetadataObject);
      return this;
    }

    public EntityMetadataInfoClaimBuilder federationEntityMetadataObject(
        final Map<String, Object> federationEntityMetadataObject) {
      this.entityMetadataInfoClaim.setFederationEntityMetadataObject(federationEntityMetadataObject);
      return this;
    }

    public EntityMetadataInfoClaimBuilder customEntityMetadataObject(String metadataTypeName, Map<String, Object> entityMetadataObject) {
      this.entityMetadataInfoClaim.setMetadataClaimsObject(metadataTypeName, entityMetadataObject);
      return this;
    }

    public EntityMetadataInfoClaim build() {
      return this.entityMetadataInfoClaim;
    }

  }


  public static class EntityMetadataInfoClaimSerializer extends JsonSerializer<EntityMetadataInfoClaim> {

    @Override
    public void serialize(EntityMetadataInfoClaim value, JsonGenerator gen, SerializerProvider serializers)
      throws IOException {
      gen.writeObject(value.getClaimObjects());
    }
  }

  public static class EntityMetadataInfoClaimDeserializer extends JsonDeserializer<EntityMetadataInfoClaim> {

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
