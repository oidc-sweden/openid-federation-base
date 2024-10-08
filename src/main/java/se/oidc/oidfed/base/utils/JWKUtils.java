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
package se.oidc.oidfed.base.utils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import lombok.NoArgsConstructor;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * JWK Utils.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class JWKUtils {

  public static JWKSBuilder jwksBuilder() {
    return new JWKSBuilder();
  }

  @NoArgsConstructor
  public static class JWKSBuilder {

    List<JWK> jwkList = new ArrayList<>();

    public JWKSBuilder addKey(final X509Certificate certificate, final String kid, final boolean includeCert)
        throws JOSEException {
      this.jwkList.add(getJwkWithKid(certificate, kid, includeCert));
      return this;
    }

    public JWKSBuilder addKey(final X509Certificate certificate, final String kid) throws JOSEException {
      this.jwkList.add(getJwkWithKid(certificate, kid, false));
      return this;
    }

    public JWKSBuilder addKey(final X509Certificate certificate) throws JOSEException {
      this.jwkList.add(JWK.parse(certificate));
      return this;
    }

    public JWKSBuilder addKey(final JWK jwk) throws JOSEException {
      this.jwkList.add(jwk);
      return this;
    }

    public JWKSet build() {
      return new JWKSet(this.jwkList);
    }
  }

  public static JWK getJwkWithKid(final X509Certificate certificate, final String kid, final boolean includeCert)
      throws JOSEException {
    if (certificate.getPublicKey() instanceof ECPublicKey) {
      return parseEcCertWithKid(certificate, kid, includeCert);
    }
    if (certificate.getPublicKey() instanceof RSAPublicKey) {
      return parseRsaCertWithKid(certificate, kid, includeCert);
    }
    throw new JOSEException("Unsupported public key algorithm: " + certificate.getPublicKey().getAlgorithm());
  }

  public static ECKey parseEcCertWithKid(final X509Certificate cert, final String kid, final boolean includeCert)
      throws JOSEException {
    if (!(cert.getPublicKey() instanceof final ECPublicKey publicKey)) {
      throw new JOSEException("The public key of the X.509 certificate is not EC");
    }
    else {

      try {
        final JcaX509CertificateHolder certHolder = new JcaX509CertificateHolder(cert);
        final String oid = certHolder.getSubjectPublicKeyInfo().getAlgorithm().getParameters().toString();
        final Curve crv = Curve.forOID(oid);
        if (crv == null) {
          throw new JOSEException("Couldn't determine EC JWK curve for OID " + oid);
        }
        else {
          final MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
          return (new ECKey.Builder(crv, publicKey))
              .keyUse(KeyUse.from(cert))
              .keyID(kid)
              .x509CertChain(includeCert ? Collections.singletonList(Base64.encode(cert.getEncoded())) : null)
              .x509CertSHA256Thumbprint(includeCert ? Base64URL.encode(sha256.digest(cert.getEncoded())) : null)
              .expirationTime(includeCert ? cert.getNotAfter() : null)
              .notBeforeTime(includeCert ? cert.getNotBefore() : null)
              .build();
        }
      }
      catch (final NoSuchAlgorithmException var6) {
        throw new JOSEException("Couldn't encode x5t parameter: " + var6.getMessage(), var6);
      }
      catch (final CertificateEncodingException var7) {
        throw new JOSEException("Couldn't encode x5c parameter: " + var7.getMessage(), var7);
      }
    }
  }

  public static RSAKey parseRsaCertWithKid(final X509Certificate cert, final String kid, final boolean includeCert)
      throws JOSEException {
    if (!(cert.getPublicKey() instanceof final RSAPublicKey publicKey)) {
      throw new JOSEException("The public key of the X.509 certificate is not RSA");
    }
    else {

      try {
        final MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        return (new RSAKey.Builder(publicKey))
            .keyUse(KeyUse.from(cert))
            .keyID(kid)
            .x509CertChain(includeCert ? Collections.singletonList(Base64.encode(cert.getEncoded())) : null)
            .x509CertSHA256Thumbprint(includeCert ? Base64URL.encode(sha256.digest(cert.getEncoded())) : null)
            .expirationTime(includeCert ? cert.getNotAfter() : null)
            .notBeforeTime(includeCert ? cert.getNotBefore() : null)
            .build();
      }
      catch (final NoSuchAlgorithmException var3) {
        throw new JOSEException("Couldn't encode x5t parameter: " + var3.getMessage(), var3);
      }
      catch (final CertificateEncodingException var4) {
        throw new JOSEException("Couldn't encode x5c parameter: " + var4.getMessage(), var4);
      }
    }
  }
}
