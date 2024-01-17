package se.swedenconnect.oidcfed.commons.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

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

/**
 * Description
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

    public JWKSBuilder addKey(X509Certificate certificate, String kid, boolean includeCert) throws JOSEException {
      jwkList.add(getJwkWithKid(certificate, kid, includeCert));
      return this;
    }
    public JWKSBuilder addKey(X509Certificate certificate, String kid) throws JOSEException {
      jwkList.add(getJwkWithKid(certificate, kid, false));
      return this;
    }
    public JWKSBuilder addKey(X509Certificate certificate) throws JOSEException {
      jwkList.add(JWK.parse(certificate));
      return this;
    }
    public JWKSBuilder addKey(JWK jwk) throws JOSEException {
      jwkList.add(jwk);
      return this;
    }

    public JWKSet build() {
      return new JWKSet(jwkList);
    }
  }

  public static JWK getJwkWithKid(X509Certificate certificate, String kid, boolean includeCert) throws JOSEException {
    if (certificate.getPublicKey() instanceof ECPublicKey) {
      return parseEcCertWithKid(certificate, kid, includeCert);
    }
    if (certificate.getPublicKey() instanceof RSAPublicKey) {
      return parseRsaCertWithKid(certificate, kid, includeCert);
    }
    throw new JOSEException("Unsupported public key algorithm: " + certificate.getPublicKey().getAlgorithm());
  }

  public static ECKey parseEcCertWithKid(X509Certificate cert, String kid, boolean includeCert) throws JOSEException {
    if (!(cert.getPublicKey() instanceof ECPublicKey)) {
      throw new JOSEException("The public key of the X.509 certificate is not EC");
    } else {
      ECPublicKey publicKey = (ECPublicKey)cert.getPublicKey();

      try {
        JcaX509CertificateHolder certHolder = new JcaX509CertificateHolder(cert);
        String oid = certHolder.getSubjectPublicKeyInfo().getAlgorithm().getParameters().toString();
        Curve crv = Curve.forOID(oid);
        if (crv == null) {
          throw new JOSEException("Couldn't determine EC JWK curve for OID " + oid);
        } else {
          MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
          return (new ECKey.Builder(crv, publicKey))
            .keyUse(KeyUse.from(cert))
            .keyID(kid)
            .x509CertChain(includeCert ? Collections.singletonList(Base64.encode(cert.getEncoded())) : null)
            .x509CertSHA256Thumbprint(includeCert ? Base64URL.encode(sha256.digest(cert.getEncoded())) : null)
            .expirationTime(includeCert ? cert.getNotAfter() : null)
            .notBeforeTime(includeCert ? cert.getNotBefore() : null)
            .build();
        }
      } catch (NoSuchAlgorithmException var6) {
        throw new JOSEException("Couldn't encode x5t parameter: " + var6.getMessage(), var6);
      } catch (CertificateEncodingException var7) {
        throw new JOSEException("Couldn't encode x5c parameter: " + var7.getMessage(), var7);
      }
    }
  }

  public static RSAKey parseRsaCertWithKid(X509Certificate cert, String kid, boolean includeCert) throws JOSEException {
    if (!(cert.getPublicKey() instanceof RSAPublicKey)) {
      throw new JOSEException("The public key of the X.509 certificate is not RSA");
    } else {
      RSAPublicKey publicKey = (RSAPublicKey)cert.getPublicKey();

      try {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        return (new RSAKey.Builder(publicKey))
          .keyUse(KeyUse.from(cert))
          .keyID(kid)
          .x509CertChain(includeCert ? Collections.singletonList(Base64.encode(cert.getEncoded())) : null)
          .x509CertSHA256Thumbprint(includeCert ? Base64URL.encode(sha256.digest(cert.getEncoded())) : null)
          .expirationTime(includeCert ? cert.getNotAfter() : null)
          .notBeforeTime(includeCert ? cert.getNotBefore() : null)
          .build();
      } catch (NoSuchAlgorithmException var3) {
        throw new JOSEException("Couldn't encode x5t parameter: " + var3.getMessage(), var3);
      } catch (CertificateEncodingException var4) {
        throw new JOSEException("Couldn't encode x5c parameter: " + var4.getMessage(), var4);
      }
    }
  }
}
