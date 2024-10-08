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
package se.oidc.oidfed.base.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * Signing credential for signing a JWT
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JWTSigningCredential {

  private List<JWSAlgorithm> supportedAlgorithms;
  private JWSSigner signer;
  private JWSVerifier verifier;
  private String kid;

  /**
   * Return the first supported algorithm that is among the permitted algorithms
   *
   * @param permittedAlgorithms permitted algorithms or null if all algorithms are premitted
   * @return first supported algorithm that is permitted
   * @throws NoSuchAlgorithmException if no supported algorithm is permitted
   */
  public JWSAlgorithm getJwsAlgorithm(final List<JWSAlgorithm> permittedAlgorithms) throws NoSuchAlgorithmException {

    if (permittedAlgorithms == null) {
      return this.supportedAlgorithms.get(0);
    }

    return this.supportedAlgorithms.stream()
        .filter(permittedAlgorithms::contains)
        .findFirst()
        .orElseThrow(() -> new NoSuchAlgorithmException("No permitted algorithm is supported"));
  }
}
