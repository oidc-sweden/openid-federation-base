package se.swedenconnect.oidcfed.commons.process.metadata;

import java.io.Serial;

/**
 * Exception for metadata policy translation errors
 */
public class PolicyTranslationException extends Exception {

  @Serial private static final long serialVersionUID = 7065232880282582329L;

  /** {@inheritDoc} */
  public PolicyTranslationException(String message) {
    super(message);
  }

  /** {@inheritDoc} */
  public PolicyTranslationException(String message, Throwable cause) {
    super(message, cause);
  }
}
