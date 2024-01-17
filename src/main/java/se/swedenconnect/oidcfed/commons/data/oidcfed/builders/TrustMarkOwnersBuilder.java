package se.swedenconnect.oidcfed.commons.data.oidcfed.builders;

import java.util.HashMap;
import java.util.Map;

import com.nimbusds.jose.jwk.JWKSet;

import se.swedenconnect.oidcfed.commons.data.oidcfed.TrustMarkOwner;

/**
 * Builder for the trust mark owners claim
 */
public class TrustMarkOwnersBuilder {

  /**
   * Trust mark owner builder
   */
  private Map<String, TrustMarkOwner> trustMarkOwners;

  /**
   * private constructor for the getInstance() function
   */
  private TrustMarkOwnersBuilder() {
    this.trustMarkOwners = new HashMap<>();
  }

  /**
   * Get an instance of this trust mark owner builder
   *
   * @return {@link TrustMarkOwnersBuilder}
   */
  public static TrustMarkOwnersBuilder getInstance() {
    return new TrustMarkOwnersBuilder();
  }

  /**
   * Add trust mark with owner information
   *
   * @param trustMark trust mark ID
   * @param owner trust mark Owner identifier
   * @param jwkSet JWK set of the trust mark owner
   * @return this builder for cascading input
   */
  public TrustMarkOwnersBuilder trustMark(String trustMark, String owner, JWKSet jwkSet) {
    trustMarkOwners.put(trustMark, new TrustMarkOwner(owner, jwkSet));
    return this;
  }

  /**
   * Build trust mark owner data
   *
   * @return trust mark owner data
   */
  public Map<String, TrustMarkOwner> build() {
    return trustMarkOwners;
  }

}
