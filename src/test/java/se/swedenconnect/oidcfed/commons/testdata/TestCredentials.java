package se.swedenconnect.oidcfed.commons.testdata;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import lombok.Getter;
import org.springframework.core.io.FileSystemResource;
import se.swedenconnect.oidcfed.commons.security.JWTSigningCredential;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;

import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Credentials for unit tests
 */
public class TestCredentials {


  @Getter
  public static PkiCredential p256Credential;
  @Getter
  public static JWTSigningCredential p256JwtCredential;
  @Getter
  public static PkiCredential p521Credential;
  @Getter
  public static JWTSigningCredential p521JwtCredential;
  @Getter
  public static PkiCredential rsa3072Credential;
  @Getter
  public static JWTSigningCredential rsa3072JwtCredential;

  // Entity credentials
  @Getter
  public static PkiCredential ta1;
  @Getter
  public static JWTSigningCredential ta1Sig;
  @Getter
  public static PkiCredential ie1;
  @Getter
  public static JWTSigningCredential ie1Sig;
  @Getter
  public static PkiCredential ie2;
  @Getter
  public static JWTSigningCredential ie2Sig;
  @Getter
  public static PkiCredential rp1;
  @Getter
  public static JWTSigningCredential rp1Sig;
  @Getter
  public static PkiCredential op1;
  @Getter
  public static JWTSigningCredential op1Sig;

  public static final char[] pwd = "Test1234".toCharArray();


  static {
    try {
      FileSystemResource keyStoreResource = new FileSystemResource(
        TestCredentials.class.getResource("/test-keys.jks").getFile());

      p256Credential = new KeyStoreCredential(keyStoreResource, pwd, "p256", pwd);
      p256Credential.init();
      p256JwtCredential = new JWTSigningCredential(List.of(JWSAlgorithm.ES256),
        new ECDSASigner((ECPrivateKey) p256Credential.getPrivateKey()), new ECDSAVerifier((ECPublicKey) p256Credential.getPublicKey()), "test_p256");
      p521Credential = new KeyStoreCredential(keyStoreResource, pwd, "p521", pwd);
      p521Credential.init();
      p521JwtCredential = new JWTSigningCredential(List.of(JWSAlgorithm.ES512),
        new ECDSASigner((ECPrivateKey) p521Credential.getPrivateKey()), new ECDSAVerifier((ECPublicKey) p521Credential.getPublicKey()), "test_p521");
      rsa3072Credential = new KeyStoreCredential(keyStoreResource, pwd, "rsa3072", pwd);
      rsa3072Credential.init();
      rsa3072JwtCredential = new JWTSigningCredential(
        List.of(JWSAlgorithm.RS256,JWSAlgorithm.RS384, JWSAlgorithm.RS512, JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512),
        new RSASSASigner(rsa3072Credential.getPrivateKey()), new RSASSAVerifier((RSAPublicKey) rsa3072Credential.getPublicKey()), "test_rsa3072");

      // Entity credentials
      ta1 = new KeyStoreCredential(keyStoreResource, pwd, "ta1", pwd);
      ta1.init();
      ta1Sig = new JWTSigningCredential(List.of(JWSAlgorithm.ES512),
        new ECDSASigner((ECPrivateKey) ta1.getPrivateKey()), new ECDSAVerifier((ECPublicKey) ta1.getPublicKey()), "test_ta1");

      ie1 = new KeyStoreCredential(keyStoreResource, pwd, "ie1", pwd);
      ie1.init();
      ie1Sig = new JWTSigningCredential(List.of(JWSAlgorithm.ES256),
        new ECDSASigner((ECPrivateKey) ie1.getPrivateKey()), new ECDSAVerifier((ECPublicKey) ie1.getPublicKey()), "test_ie1");

      ie2 = new KeyStoreCredential(keyStoreResource, pwd, "ie2", pwd);
      ie2.init();
      ie2Sig = new JWTSigningCredential(
        List.of(JWSAlgorithm.RS256,JWSAlgorithm.RS384, JWSAlgorithm.RS512, JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512),
        new RSASSASigner(ie2.getPrivateKey()), new RSASSAVerifier((RSAPublicKey) ie2.getPublicKey()), "test_ie2");

      rp1 = new KeyStoreCredential(keyStoreResource, pwd, "rp1", pwd);
      rp1.init();
      rp1Sig = new JWTSigningCredential(List.of(JWSAlgorithm.ES256),
        new ECDSASigner((ECPrivateKey) rp1.getPrivateKey()), new ECDSAVerifier((ECPublicKey) rp1.getPublicKey()), "test_rp1");

      op1 = new KeyStoreCredential(keyStoreResource, pwd, "op1", pwd);
      op1.init();
      op1Sig = new JWTSigningCredential(List.of(JWSAlgorithm.ES256),
        new ECDSASigner((ECPrivateKey) op1.getPrivateKey()), new ECDSAVerifier((ECPublicKey) op1.getPublicKey()), "test_op1");

    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }


  public static JWKSet getJwkSet(X509Certificate... certificate) {

    return new JWKSet(
      Arrays.stream(certificate)
        .map(cert -> {
          try {
            return JWK.parse(cert);
          }
          catch (JOSEException e) {
            throw new RuntimeException(e);
          }
        })
        .collect(Collectors.toList())
    );

  }


}
