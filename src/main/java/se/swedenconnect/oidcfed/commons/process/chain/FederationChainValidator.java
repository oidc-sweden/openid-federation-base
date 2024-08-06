package se.swedenconnect.oidcfed.commons.process.chain;

import java.util.List;

import se.swedenconnect.oidcfed.commons.data.oidcfed.EntityStatement;

/**
 * Chain validator interface used to validate federation data through chain validation
 */
public interface FederationChainValidator {

  /**
   * Validates a chain from Trust Anchor to target entity and process metadata through the policies of the chain.
   *
   * <p>
   *   This function does not validate the Trust Marks of the leaf statement. Trust Mark validation is a separate
   *   process that in itself will use this function for chain validation of Trust Mark Issuers.
   * </p>
   *
   * <p>
   *   In the standard, a chain starts with the target Entity and ends with the Trust Anchor. However, the validation
   *   process is processing the chain from Trust Anchor to target entity in order to validate the superior entity
   *   key before it is used to validate the data of the subordinate. This is the natural processing order. Paths can
   *   be provided in any order as the first step of the validation process is to arrange the path Entity Statements in the
   *   correct order.
   * </p>
   *
   * @param chain the trust chain starting from the Trust Anchor Entity Configuration and ending with the target Entity Configuration
   * @return chain validation result
   * @throws ChainValidationException errors validating the chain
   */
  ChainValidationResult validate(List<EntityStatement> chain) throws ChainValidationException;

}
