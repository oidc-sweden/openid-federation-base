package se.swedenconnect.oidcfed.commons.data.oidcfed;

import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;

/**
 * Metadata claims data for both the metadata claim and the metadata_policy claim
 */
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class EntityMetadataInfoClaim {

  protected EntityMetadataInfoClaim() {
  }

  @JsonProperty("openid_relying_party")
  protected Map<String, Object> oidcRelyingPartyMetadataObject;

  @JsonProperty("openid_provider")
  protected Map<String, Object> opMetadataObject;

  @JsonProperty("oauth_authorization_server")
  protected Map<String, Object> authorizationServerMetadataObject;

  @JsonProperty("oauth_client")
  protected Map<String, Object> oauthClientMetadataObject;

  @JsonProperty("oauth_resource")
  protected Map<String, Object> oauthResourceMetadataObject;

  @JsonProperty("federation_entity")
  protected Map<String, Object> federationEntityMetadataObject;

  public static EntityMetadataInfoClaimBuilder builder() {
    return new EntityMetadataInfoClaimBuilder();
  }

  public static class EntityMetadataInfoClaimBuilder {

    private final EntityMetadataInfoClaim entityMetadataInfoClaim;

    private EntityMetadataInfoClaimBuilder() {
      this.entityMetadataInfoClaim = new EntityMetadataInfoClaim();
    }

    public EntityMetadataInfoClaimBuilder oidcRelyingPartyMetadataObject(Map<String, Object> oidcRelyingPartyMetadataObject) {
      this.entityMetadataInfoClaim.oidcRelyingPartyMetadataObject = oidcRelyingPartyMetadataObject;
      return this;
    }
    public EntityMetadataInfoClaimBuilder opMetadataObject(Map<String, Object> opMetadataObject) {
      this.entityMetadataInfoClaim.opMetadataObject = opMetadataObject;
      return this;
    }
    public EntityMetadataInfoClaimBuilder authorizationServerMetadataObject(Map<String, Object> authorizationServerMetadataObject) {
      this.entityMetadataInfoClaim.authorizationServerMetadataObject = authorizationServerMetadataObject;
      return this;
    }
    public EntityMetadataInfoClaimBuilder oauthClientMetadataObject(Map<String, Object> oauthClientMetadataObject) {
      this.entityMetadataInfoClaim.oauthClientMetadataObject = oauthClientMetadataObject;
      return this;
    }
    public EntityMetadataInfoClaimBuilder oauthResourceMetadataObject(Map<String, Object> oauthResourceMetadataObject) {
      this.entityMetadataInfoClaim.oauthResourceMetadataObject = oauthResourceMetadataObject;
      return this;
    }
    public EntityMetadataInfoClaimBuilder federationEntityMetadataObject(Map<String, Object> federationEntityMetadataObject) {
      this.entityMetadataInfoClaim.federationEntityMetadataObject = federationEntityMetadataObject;
      return this;
    }

    public EntityMetadataInfoClaim build(){
      return this.entityMetadataInfoClaim;
    }


  }

}
