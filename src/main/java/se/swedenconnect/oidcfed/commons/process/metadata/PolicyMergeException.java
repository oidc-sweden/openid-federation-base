package se.swedenconnect.oidcfed.commons.process.metadata;

import java.io.Serial;

/**
 */
public class PolicyMergeException extends Exception {
  @Serial private static final long serialVersionUID = -1937970416867894743L;

  /** {@inheritDoc} */
  public PolicyMergeException(String message) {
    super(message);
  }

  /** {@inheritDoc} */
  public PolicyMergeException(String message, Throwable cause) {
    super(message, cause);
  }
}
