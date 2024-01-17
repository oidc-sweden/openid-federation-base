package se.swedenconnect.oidcfed.commons.process.chain;

import java.io.Serial;

import lombok.Getter;

/**
 * Exception for Trust Mark status errors
 */
public class TrustMarkStatusException extends Exception {

  @Serial private static final long serialVersionUID = -7799916022228631630L;

  @Getter String error;

  /** {@inheritDoc} */
  public TrustMarkStatusException(String error, String message) {
    super(message);
    this.error = error;
  }

  /** {@inheritDoc} */
  public TrustMarkStatusException(String error, String message, Throwable cause) {
    super(message, cause);
    this.error = error;
  }

}
