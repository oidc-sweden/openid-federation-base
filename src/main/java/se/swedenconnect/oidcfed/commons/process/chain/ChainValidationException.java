package se.swedenconnect.oidcfed.commons.process.chain;

import java.io.Serial;

/**
 * Exception for federation chain validation errors
 */
public class ChainValidationException extends Exception{
  @Serial private static final long serialVersionUID = 7340001608971248505L;

  /**  {@inheritDoc} */
  public ChainValidationException(String message) {
    super(message);
  }

  /**  {@inheritDoc} */
  public ChainValidationException(String message, Throwable cause) {
    super(message, cause);
  }
}
