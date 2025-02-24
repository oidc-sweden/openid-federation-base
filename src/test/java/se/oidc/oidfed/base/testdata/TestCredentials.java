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
package se.oidc.oidfed.base.testdata;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import lombok.Getter;
import se.oidc.oidfed.base.security.JWTSigningCredential;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;

import java.io.InputStream;
import java.security.KeyStore;
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
    try (InputStream keyStoreStream = TestCredentials.class.getResourceAsStream("/test-keys.jks")) {

      KeyStore keyStore = KeyStore.getInstance("JKS");
      keyStore.load(keyStoreStream, pwd);




      p256Credential = new KeyStoreCredential(keyStore, "p256", pwd);
      p256JwtCredential = new JWTSigningCredential(List.of(JWSAlgorithm.ES256),
          new ECDSASigner((ECPrivateKey) p256Credential.getPrivateKey()),
          new ECDSAVerifier((ECPublicKey) p256Credential.getPublicKey()), "test_p256");
      p521Credential = new KeyStoreCredential(keyStore, "p521", pwd);
      p521JwtCredential = new JWTSigningCredential(List.of(JWSAlgorithm.ES512),
          new ECDSASigner((ECPrivateKey) p521Credential.getPrivateKey()),
          new ECDSAVerifier((ECPublicKey) p521Credential.getPublicKey()), "test_p521");
      rsa3072Credential = new KeyStoreCredential(keyStore, "rsa3072", pwd);
      rsa3072JwtCredential = new JWTSigningCredential(
          List.of(JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512, JWSAlgorithm.PS256, JWSAlgorithm.PS384,
              JWSAlgorithm.PS512),
          new RSASSASigner(rsa3072Credential.getPrivateKey()),
          new RSASSAVerifier((RSAPublicKey) rsa3072Credential.getPublicKey()), "test_rsa3072");

      // Entity credentials
      ta1 = new KeyStoreCredential(keyStore, "ta1", pwd);
      ta1Sig = new JWTSigningCredential(List.of(JWSAlgorithm.ES512),
          new ECDSASigner((ECPrivateKey) ta1.getPrivateKey()), new ECDSAVerifier((ECPublicKey) ta1.getPublicKey()),
          "test_ta1");

      ie1 = new KeyStoreCredential(keyStore, "ie1", pwd);
      ie1Sig = new JWTSigningCredential(List.of(JWSAlgorithm.ES256),
          new ECDSASigner((ECPrivateKey) ie1.getPrivateKey()), new ECDSAVerifier((ECPublicKey) ie1.getPublicKey()),
          "test_ie1");

      ie2 = new KeyStoreCredential(keyStore, "ie2", pwd);
      ie2Sig = new JWTSigningCredential(
          List.of(JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512, JWSAlgorithm.PS256, JWSAlgorithm.PS384,
              JWSAlgorithm.PS512),
          new RSASSASigner(ie2.getPrivateKey()), new RSASSAVerifier((RSAPublicKey) ie2.getPublicKey()), "test_ie2");

      rp1 = new KeyStoreCredential(keyStore, "rp1", pwd);
      rp1Sig = new JWTSigningCredential(List.of(JWSAlgorithm.ES256),
          new ECDSASigner((ECPrivateKey) rp1.getPrivateKey()), new ECDSAVerifier((ECPublicKey) rp1.getPublicKey()),
          "test_rp1");

      op1 = new KeyStoreCredential(keyStore, "op1", pwd);
      op1Sig = new JWTSigningCredential(List.of(JWSAlgorithm.ES256),
          new ECDSASigner((ECPrivateKey) op1.getPrivateKey()), new ECDSAVerifier((ECPublicKey) op1.getPublicKey()),
          "test_op1");

    }
    catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static JWKSet getJwkSet(final X509Certificate... certificate) {

    return new JWKSet(
        Arrays.stream(certificate)
            .map(cert -> {
              try {
                return JWK.parse(cert);
              }
              catch (final JOSEException e) {
                throw new RuntimeException(e);
              }
            })
            .collect(Collectors.toList())
    );

  }

}
