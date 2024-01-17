package se.swedenconnect.oidcfed.commons.data.oidcfed;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.jwk.JWKSet;

import lombok.Getter;

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

  @JsonProperty("subject_data_publication")
  private SubjectDataPublication subjectDataPublication;

  public static EntityStatementDefinedParamsBuilder builder() {
    return new EntityStatementDefinedParamsBuilder();
  }

  public static class EntityStatementDefinedParamsBuilder {

    private EntityStatementDefinedParams esDefinedParams = new EntityStatementDefinedParams();
    private EntityStatementDefinedParamsBuilder() {
    }

    public EntityStatementDefinedParamsBuilder jwkSet(JWKSet jwkSet) {
      esDefinedParams.jwkSet = jwkSet.toJSONObject();
      return this;
    }

    /** MUST be present in Entity Configuration that is NOT a TA. MUST NOT be present in other statements */
    public EntityStatementDefinedParamsBuilder authorityHints(List<String> authorityHints) {
      esDefinedParams.authorityHints = authorityHints;
      return this;
    }

    /** Fetch endpoint URL where this statement was obtained */
    public EntityStatementDefinedParamsBuilder sourceEndpoint(String sourceEndpoint) {
      esDefinedParams.sourceEndpoint = sourceEndpoint;
      return this;
    }
    public EntityStatementDefinedParamsBuilder metadata(EntityMetadataInfoClaim metadata) {
      esDefinedParams.metadata = metadata;
      return this;
    }
    public EntityStatementDefinedParamsBuilder metadataPolicy(EntityMetadataInfoClaim metadataPolicy) {
      esDefinedParams.metadataPolicy = metadataPolicy;
      return this;
    }

    /** Can be present in the full path. All constraints of the path MUST be honored */
    public EntityStatementDefinedParamsBuilder constraints(ConstraintsClaim constraints) {
      esDefinedParams.constraints = constraints;
      return this;
    }

    public EntityStatementDefinedParamsBuilder addCriticalClaim(String criticalClaim) {
      List<String> criticalClaims = Optional.ofNullable(esDefinedParams.criticalClaims).orElse(new ArrayList<>());
      if (!criticalClaims.contains(criticalClaim)){
        criticalClaims.add(criticalClaim);
        this.esDefinedParams.criticalClaims = criticalClaims;
      }
      return this;
    }
    public EntityStatementDefinedParamsBuilder addPolicyLanguageCriticalClaim(String metadataPolicyCriticalClaim) {
      List<String> metadataPolicyCriticalClaims = Optional.ofNullable(esDefinedParams.metadataPolicyCriticalClaims).orElse(new ArrayList<>());
      if (!metadataPolicyCriticalClaims.contains(metadataPolicyCriticalClaim)){
        metadataPolicyCriticalClaims.add(metadataPolicyCriticalClaim);
        this.esDefinedParams.metadataPolicyCriticalClaims = metadataPolicyCriticalClaims;
      }
      return this;
    }
    public EntityStatementDefinedParamsBuilder trustMarks(List<TrustMarkClaim> trustMarks) {
      esDefinedParams.trustMarks = trustMarks;
      return this;
    }
    public EntityStatementDefinedParamsBuilder trustMarkIssuers(Map<String, List<String>> trustMarkIssuers) {
      esDefinedParams.trustMarkIssuers = trustMarkIssuers;
      return this;
    }
    public EntityStatementDefinedParamsBuilder trustMarkOwners(Map<String, TrustMarkOwner> trustMarkOwners) {
      esDefinedParams.trustMarkOwners = trustMarkOwners;
      return this;
    }

    public EntityStatementDefinedParamsBuilder subjectDataPublication(SubjectDataPublication subjectDataPublication, boolean critical) {
      esDefinedParams.subjectDataPublication = subjectDataPublication;
      if (critical) {
        this.addCriticalClaim(SubjectDataPublication.CLAIM_NAME);
      }
      return this;
    }

    public EntityStatementDefinedParams build() {
      return esDefinedParams;
    }

  }

}
