package se.swedenconnect.oidcfed.commons.data.oidcfed;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jwt.SignedJWT;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Trust Mark
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TrustMarkClaim {

  @JsonProperty("id")
  private String id;

  @JsonProperty("trust_mark")
  private String trustMark;

}
