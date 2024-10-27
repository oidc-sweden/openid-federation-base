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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.Map;

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

    public EntityMetadataInfoClaimBuilder oidcRelyingPartyMetadataObject(
        final Map<String, Object> oidcRelyingPartyMetadataObject) {
      this.entityMetadataInfoClaim.oidcRelyingPartyMetadataObject = oidcRelyingPartyMetadataObject;
      return this;
    }

    public EntityMetadataInfoClaimBuilder opMetadataObject(final Map<String, Object> opMetadataObject) {
      this.entityMetadataInfoClaim.opMetadataObject = opMetadataObject;
      return this;
    }

    public EntityMetadataInfoClaimBuilder authorizationServerMetadataObject(
        final Map<String, Object> authorizationServerMetadataObject) {
      this.entityMetadataInfoClaim.authorizationServerMetadataObject = authorizationServerMetadataObject;
      return this;
    }

    public EntityMetadataInfoClaimBuilder oauthClientMetadataObject(
        final Map<String, Object> oauthClientMetadataObject) {
      this.entityMetadataInfoClaim.oauthClientMetadataObject = oauthClientMetadataObject;
      return this;
    }

    public EntityMetadataInfoClaimBuilder oauthResourceMetadataObject(
        final Map<String, Object> oauthResourceMetadataObject) {
      this.entityMetadataInfoClaim.oauthResourceMetadataObject = oauthResourceMetadataObject;
      return this;
    }

    public EntityMetadataInfoClaimBuilder federationEntityMetadataObject(
        final Map<String, Object> federationEntityMetadataObject) {
      this.entityMetadataInfoClaim.federationEntityMetadataObject = federationEntityMetadataObject;
      return this;
    }

    public EntityMetadataInfoClaim build() {
      return this.entityMetadataInfoClaim;
    }

  }

}
