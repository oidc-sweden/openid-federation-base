package se.swedenconnect.oidcfed.commons.process.chain;

import java.util.List;

import se.swedenconnect.oidcfed.commons.data.oidcfed.EntityStatement;

/**
 * Chain path builder for OpenID federation
 */
public interface FederationPathBuilder {

  /**
   * Builds a path of entity statements starting from the given entity identifier and ending at the trust anchor.
   *
   * @param entityIdentifier The identifier of the starting entity.
   * @param trustAnchor The trust anchor entity identifier.
   * @return The list of entity statements forming the path from the starting entity to the trust anchor.
   * @throws PathBuildingException If there is an error building the path.
   */
  List<EntityStatement> buildPath(String entityIdentifier, String trustAnchor) throws PathBuildingException;

}
