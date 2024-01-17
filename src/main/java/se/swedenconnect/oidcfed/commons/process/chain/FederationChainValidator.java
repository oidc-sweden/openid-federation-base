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
   * @param chain the trust chain from a leaf entity data statement to a trust anchor entity configuration statement
   * @return chain validation result
   * @throws ChainValidationException errors validating the chain
   */
  ChainValidationResult validate(List<EntityStatement> chain) throws ChainValidationException;

}
