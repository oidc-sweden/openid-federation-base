package se.swedenconnect.oidcfed.commons.process.metadata;

import java.io.Serial;

/**
 * Exception caused by errors during metadata policy processing
 */
public class PolicyProcessingException extends Exception {

  @Serial private static final long serialVersionUID = 1107858985504144682L;

  /** {@inheritDoc} */
  public PolicyProcessingException(String message) {
    super(message);
  }

  /** {@inheritDoc} */
  public PolicyProcessingException(String message, Throwable cause) {
    super(message, cause);
  }
}
