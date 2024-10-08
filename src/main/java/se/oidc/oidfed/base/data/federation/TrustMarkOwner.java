/*
 * Copyright 2024 OIDC Sweden
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.oidc.oidfed.base.data.federation;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.jwk.JWKSet;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.text.ParseException;
import java.util.Map;
import java.util.Objects;

/**
 * Trust Mark Owner data for trust_mark_owners claim
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@NoArgsConstructor
public class TrustMarkOwner {

  public TrustMarkOwner(final String subject, final JWKSet jwkSet) {
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
