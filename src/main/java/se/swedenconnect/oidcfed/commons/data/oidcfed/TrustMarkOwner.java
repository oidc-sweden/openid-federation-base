package se.swedenconnect.oidcfed.commons.data.oidcfed;

import java.text.ParseException;
import java.util.Map;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.jwk.JWKSet;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * Trust Mark Owner data for trust_mark_owners claim
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@NoArgsConstructor
public class TrustMarkOwner {

  public TrustMarkOwner(String subject, JWKSet jwkSet) {
    Objects.requireNonNull(jwkSet, "Trust mark owner JWK set must not be null");
    Objects.requireNonNull(subject, "Trust mark owner subject name must not be null");
    this.subject = subject;
    this.jwkSet = jwkSet.toJSONObject();
  }

  @Getter
  @JsonProperty("sub")
  private String subject;

  @JsonProperty("jwks")
  private Map<String, Object> jwkSet;

  @JsonIgnore
  public JWKSet getJwkSet() throws ParseException {
    return JWKSet.parse(this.jwkSet);
  }


}
