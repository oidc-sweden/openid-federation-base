package se.swedenconnect.oidcfed.commons.process.chain;

import java.util.List;

import se.swedenconnect.oidcfed.commons.data.oidcfed.EntityStatement;

/**
 * Chain path builder for OpenID federation
 */
public interface FederationPathBuilder {

  List<EntityStatement> buildPath(String entityIdentifier, String trustAnchor) throws PathBuildingException;

}
