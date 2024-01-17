package se.swedenconnect.oidcfed.commons.data.metadata;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.oidcfed.commons.data.LanguageObject;
import se.swedenconnect.oidcfed.commons.testdata.TestCredentials;

/**
 * Tests for supported metadata types
 */
@Slf4j
class MetadataTests {


  @Test
  void resourceServerMetadataTest() throws Exception {

    ResourceServerMetadata resourceServerMetadata = ResourceServerMetadata.builder()
      .contacts(List.of("nisse@example.com", "jd@example.com"))
      .homepageUri("https://example.com/homepage")
      .jwkSet(new JWKSet(List.of(JWK.parse(TestCredentials.getP521Credential().getCertificate()))))
      .jwksUri("https://example.com/jwks-uri")
      .signedJwksUri("https://example.com/signed-jwks-uri")
      .policyUri("https://example.com/policy")
      .logoUri(LanguageObject.builder(String.class)
        .defaultValue("https://example.com/logo")
        .langValue("en", "https://example.com/en-logo")
        .build())
      .organizationName(LanguageObject.builder(String.class)
        .defaultValue("Organization")
        .langValue("en", "English Organization name")
        .build())
      .build();

    assertNotNull(resourceServerMetadata);
    logMetadataValues(resourceServerMetadata);

    log.info("Parsing metadata JSON object");
    ResourceServerMetadata parsedMetadata = ResourceServerMetadata.getJsonSerializer()
      .parse(resourceServerMetadata.toJsonObject());

    // Test JWKS
    JWKSet jwkSet = parsedMetadata.getJwkSet();
    assertNotNull(jwkSet);
    parsedMetadata.setJwkSet(new JWKSet(List.of(JWK.parse(TestCredentials.getRsa3072Credential().getCertificate()))));
    logMetadataValues(parsedMetadata);
  }

  private void logMetadataValues(AbstractOidcFedMetadata metadata) throws Exception {

    String metadataJson = metadata.toJson(true);
    log.info("Content of {}\n{}", metadata.getClass().getSimpleName(), metadataJson);

  }

  @Test
  void testRelyingPartyMetadata() throws Exception {

    RelyingPartyMetadata relyingPartyMetadata = RelyingPartyMetadata.builder()
      .requireAuthTime(true)
      .defaultMaxAge(240)
      .applicationType("type")
      .defaultAcrValues(List.of("loa3", "loa4"))
      .idTokenEncryptedResponseAlg("alg")
      .initiateLoginUri("uri")
      .idTokenSignedResponseAlg("alg")
      .idTokenEncryptedResponseAlg("alg")
      .requestObjectEncryptionAlg("alg")
      .requestObjectEncryptionAlg("alg")
      .requestObjectEncryptionEnc("alg")
      .tokenEndpointAuthSigningAlg("alg")
      .tokenEndpointAuthMethod("private_key_jwt")
      .userinfoSignedResponseAlg("alg")
      .userinfoEncryptedResponseEnc("alg")
      .userinfoEncryptedResponseAlg("alg")
      .clientName(LanguageObject.builder(String.class)
        .defaultValue("Client name")
        .langValue("sv", "Klientnamn")
        .build())
      .clientUri("uri")
      .grantTypes(List.of("type1", "type2"))
      .redirectUris(List.of("Redirect URI", "Redirect URI2"))
      .responseTypes(List.of("Response types"))
      .signedJwksUri("signed JWKS URI")
      .contacts(List.of("nisse@example.com", "jd@example.com"))
      .homepageUri("https://example.com/homepage")
      .jwkSet(new JWKSet(List.of(JWK.parse(TestCredentials.getP521Credential().getCertificate()))))
      .jwksUri("https://example.com/jwks-uri")
      .signedJwksUri("https://example.com/signed-jwks-uri")
      .policyUri("https://example.com/policy")
      .logoUri(LanguageObject.builder(String.class)
        .defaultValue("https://example.com/logo")
        .langValue("en", "https://example.com/en-logo")
        .build())
      .organizationName(LanguageObject.builder(String.class)
        .defaultValue("Organization")
        .langValue("en", "English Organization name")
        .build())
      .build();

    assertNotNull(relyingPartyMetadata);
    logMetadataValues(relyingPartyMetadata);

    log.info("Parsing metadata JSON object");
    RelyingPartyMetadata parsedMetadata = RelyingPartyMetadata.getJsonSerializer()
      .parse(relyingPartyMetadata.toJsonObject());

    // Test JWKS
    JWKSet jwkSet = parsedMetadata.getJwkSet();
    assertNotNull(jwkSet);
    parsedMetadata.setJwkSet(new JWKSet(List.of(JWK.parse(TestCredentials.getRsa3072Credential().getCertificate()))));
    logMetadataValues(parsedMetadata);

  }

  @Test
  void testOpMetadata() throws Exception {
    OpMetadata opMetadata = OpMetadata.builder()
      .build();
    // TODO write test
  }

  @Test
  void testAsMetadta() throws Exception {
    AuthorizationServerMetadata authorizationServerMetadata = AuthorizationServerMetadata.builder()
      .build();


    // TODO write AS metadata test
  }

  @Test
  void testClientMetadata() throws Exception {
    ClientMetadata clientMetadata = ClientMetadata.builder()
      .build();
    // TODO write Client metadata test
  }

  @Test
  void testFederationEndpointMetadata() throws Exception {
    FederationEndpointMetadata federationEndpointMetadata = FederationEndpointMetadata.builder()
      .build();

    // TODO write FE metadata test
  }

}