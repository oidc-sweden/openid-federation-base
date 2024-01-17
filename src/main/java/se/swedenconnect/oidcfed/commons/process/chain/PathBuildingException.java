package se.swedenconnect.oidcfed.commons.process.chain;

import java.io.Serial;

/**
 * Exception for path building errors
 */
public class PathBuildingException extends Exception{

  @Serial private static final long serialVersionUID = -2121535255445628109L;

  /** {@inheritDoc} */
  public PathBuildingException(String message) {
    super(message);
  }

  /** {@inheritDoc} */
  public PathBuildingException(String message, Throwable cause) {
    super(message, cause);
  }
}
