package se.swedenconnect.oidcfed.commons.process.chain;

import java.util.List;

import se.swedenconnect.oidcfed.commons.data.oidcfed.TrustMark;

/**
 * Trust Mark Validator interface
 */
public interface TrustMarkValidator {

  List<TrustMark> validateTrustMarks(List<TrustMark> trustMarks, String subject, String trustAnchor) throws ChainValidationException;


}
