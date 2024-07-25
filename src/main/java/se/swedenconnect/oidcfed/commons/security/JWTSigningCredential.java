package se.swedenconnect.oidcfed.commons.security;

import java.security.NoSuchAlgorithmException;
import java.util.List;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

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
  public JWSAlgorithm getJwsAlgorithm(List<JWSAlgorithm> permittedAlgorithms) throws NoSuchAlgorithmException {

    if (permittedAlgorithms == null) {
      return supportedAlgorithms.get(0);
    }

    return supportedAlgorithms.stream()
      .filter(supportedAlgorithm -> permittedAlgorithms.contains(supportedAlgorithm))
      .findFirst()
      .orElseThrow(() -> new NoSuchAlgorithmException("No permitted algorithm is supported"));
  }
}
