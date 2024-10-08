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
import com.nimbusds.jose.jwk.JWKSet;
import lombok.Getter;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Getter
@JsonInclude(JsonInclude.Include.NON_NULL)
public class EntityStatementDefinedParams {

  private EntityStatementDefinedParams() {
  }

  @JsonProperty("jwks")
  private Map<String, Object> jwkSet;

  @JsonProperty("authority_hints")
  private List<String> authorityHints;

  @JsonProperty("source_endpoint")
  private String sourceEndpoint;

  @JsonProperty("metadata")
  private EntityMetadataInfoClaim metadata;

  @JsonProperty("metadata_policy")
  private EntityMetadataInfoClaim metadataPolicy;

  @JsonProperty("constraints")
  private ConstraintsClaim constraints;

  @JsonProperty("crit")
  private List<String> criticalClaims;

  @JsonProperty("metadata_policy_crit")
  private List<String> metadataPolicyCriticalClaims;

  @JsonProperty("trust_marks")
  private List<TrustMarkClaim> trustMarks;

  @JsonProperty("trust_marks_issuers")
  private Map<String, List<String>> trustMarkIssuers;

  @JsonProperty("trust_mark_owners")
  private Map<String, TrustMarkOwner> trustMarkOwners;

  @JsonProperty("subject_entity_configuration_location")
  private String subjectEntityConfigurationLocation;

  public static EntityStatementDefinedParamsBuilder builder() {
    return new EntityStatementDefinedParamsBuilder();
  }

  public static class EntityStatementDefinedParamsBuilder {

    private final EntityStatementDefinedParams esDefinedParams = new EntityStatementDefinedParams();

    private EntityStatementDefinedParamsBuilder() {
    }

    public EntityStatementDefinedParamsBuilder jwkSet(final JWKSet jwkSet) {
      this.esDefinedParams.jwkSet = jwkSet.toJSONObject();
      return this;
    }

    /** MUST be present in Entity Configuration that is NOT a TA. MUST NOT be present in other statements */
    public EntityStatementDefinedParamsBuilder authorityHints(final List<String> authorityHints) {
      this.esDefinedParams.authorityHints = authorityHints;
      return this;
    }

    /** Fetch endpoint URL where this statement was obtained */
    public EntityStatementDefinedParamsBuilder sourceEndpoint(final String sourceEndpoint) {
      this.esDefinedParams.sourceEndpoint = sourceEndpoint;
      return this;
    }

    public EntityStatementDefinedParamsBuilder metadata(final EntityMetadataInfoClaim metadata) {
      this.esDefinedParams.metadata = metadata;
      return this;
    }

    public EntityStatementDefinedParamsBuilder metadataPolicy(final EntityMetadataInfoClaim metadataPolicy) {
      this.esDefinedParams.metadataPolicy = metadataPolicy;
      return this;
    }

    /** Can be present in the full path. All constraints of the path MUST be honored */
    public EntityStatementDefinedParamsBuilder constraints(final ConstraintsClaim constraints) {
      this.esDefinedParams.constraints = constraints;
      return this;
    }

    public EntityStatementDefinedParamsBuilder addCriticalClaim(final String criticalClaim) {
      final List<String> criticalClaims =
          Optional.ofNullable(this.esDefinedParams.criticalClaims).orElse(new ArrayList<>());
      if (!criticalClaims.contains(criticalClaim)) {
        criticalClaims.add(criticalClaim);
        this.esDefinedParams.criticalClaims = criticalClaims;
      }
      return this;
    }

    public EntityStatementDefinedParamsBuilder addPolicyLanguageCriticalClaim(
        final String metadataPolicyCriticalClaim) {
      final List<String> metadataPolicyCriticalClaims =
          Optional.ofNullable(this.esDefinedParams.metadataPolicyCriticalClaims).orElse(new ArrayList<>());
      if (!metadataPolicyCriticalClaims.contains(metadataPolicyCriticalClaim)) {
        metadataPolicyCriticalClaims.add(metadataPolicyCriticalClaim);
        this.esDefinedParams.metadataPolicyCriticalClaims = metadataPolicyCriticalClaims;
      }
      return this;
    }

    public EntityStatementDefinedParamsBuilder trustMarks(final List<TrustMarkClaim> trustMarks) {
      this.esDefinedParams.trustMarks = trustMarks;
      return this;
    }

    public EntityStatementDefinedParamsBuilder trustMarkIssuers(final Map<String, List<String>> trustMarkIssuers) {
      this.esDefinedParams.trustMarkIssuers = trustMarkIssuers;
      return this;
    }

    public EntityStatementDefinedParamsBuilder trustMarkOwners(final Map<String, TrustMarkOwner> trustMarkOwners) {
      this.esDefinedParams.trustMarkOwners = trustMarkOwners;
      return this;
    }

    public EntityStatementDefinedParamsBuilder subjectEntityConfigurationLocation(
        final String subjectEntityConfigurationLocation, final boolean critical) {
      this.esDefinedParams.subjectEntityConfigurationLocation = subjectEntityConfigurationLocation;
      if (critical) {
        this.addCriticalClaim(EntityStatement.SUBJECT_ENTITY_CONFIGURATION_LOCATION_CLAIM_NAME);
      }
      return this;
    }

    public EntityStatementDefinedParams build() {
      return this.esDefinedParams;
    }

  }

}
