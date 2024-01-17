package se.swedenconnect.oidcfed.commons.data.oidcfed.builders;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Builder for trust mark issuers claim
 */
public class TrustMarkIssuersBuilder {

  Map<String, List<String>> trustMarkIssuers;

  /**
   * Private constructor for the get instance method
   */
  private TrustMarkIssuersBuilder() {
    trustMarkIssuers = new HashMap<>();
  }

  /**
   * Get an instance of the trust mark issuers builder
   *
   * @return {@link TrustMarkIssuersBuilder}
   */
  public static TrustMarkIssuersBuilder getInstance() {
    return new TrustMarkIssuersBuilder();
  }

  /**
   * Add trust mark and authorized issuers of this trust mark
   *
   * @param trustMarkId id of the trust mark
   * @param issuers list of authorized issuers entity ID
   * @return this builder for cascading input
   */
  public TrustMarkIssuersBuilder trustMark(String trustMarkId, List<String> issuers) {
    trustMarkIssuers.put(trustMarkId, issuers);
    return this;
  }

  /**
   * Build the resulting trust mark issuers data
   *
   * @return trust mark issuers data
   */
  public Map<String, List<String>> build() {
    return trustMarkIssuers;
  }

}
