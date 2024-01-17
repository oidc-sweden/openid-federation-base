package se.swedenconnect.oidcfed.commons.process.chain;

/**
 * Interface for a resolver that provides Trust Mark revocation data information.
 */
public interface TrustMarkStatusResolver {

  boolean isStatusActive(String trustMarkId, String subject, String issuer) throws TrustMarkStatusException;

}
