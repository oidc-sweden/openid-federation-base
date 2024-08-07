package se.swedenconnect.oidcfed.commons.process.chain;

import java.util.List;

import se.swedenconnect.oidcfed.commons.data.oidcfed.EntityStatement;

/**
 * Chain path builder for OpenID federation
 */
public interface FederationPathBuilder {

  /**
   * Builds a path of entity statements in the selected order.
   *
   * <p>
   *   Note that the order of a chain described in the OpenID federation standard which starts with the leaf and
   *   ends with the Trust Anchor. However a top-down path is more naturally to build and to validate and is the order
   *   the path is processed by the validator. If this path is exposed externally, use the buildPath function and specify
   *   trustAnchorFirst to false.
   * </p>
   *
   * @param entityIdentifier the identifier of the starting entity.
   * @param trustAnchor the trust anchor entity identifier.
   * @param trustAnchorFirst the value of true places the Trust Anchor first in the chain, otherwise last
   * @return the list of entity statements forming the path from the starting entity to the trust anchor.
   * @throws PathBuildingException If there is an error building the path.
   */

  public List<EntityStatement> buildPath(String entityIdentifier, String trustAnchor, boolean trustAnchorFirst)
    throws PathBuildingException;
}
