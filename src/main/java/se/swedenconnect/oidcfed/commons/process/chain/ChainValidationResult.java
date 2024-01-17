package se.swedenconnect.oidcfed.commons.process.chain;

import java.util.List;
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.swedenconnect.oidcfed.commons.data.oidcfed.EntityMetadataInfoClaim;
import se.swedenconnect.oidcfed.commons.data.oidcfed.EntityStatement;
import se.swedenconnect.oidcfed.commons.data.oidcfed.TrustMarkClaim;

/**
 * Result data from chain validation
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ChainValidationResult {

  /** The validated chain */
  List<EntityStatement> validatedChain;
  // The declared metadata of the target
  EntityMetadataInfoClaim declaredMetadata;
  // Process metadata against policy
  EntityMetadataInfoClaim policyProcessedMetadata;
  // Trust marks for the subject to be validated
  List<TrustMarkClaim> subjectTrustMarks;

}
