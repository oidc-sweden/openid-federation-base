package se.swedenconnect.oidcfed.commons.data.oidcfed;

import static org.junit.jupiter.api.Assertions.*;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.oidcfed.commons.data.LanguageObject;
import se.swedenconnect.oidcfed.commons.data.metadata.OpMetadata;
import se.swedenconnect.oidcfed.commons.data.metadata.RelyingPartyMetadata;
import se.swedenconnect.oidcfed.commons.data.metadata.policy.EntityTypeMetadataPolicy;
import se.swedenconnect.oidcfed.commons.data.metadata.policy.MetadataParameterPolicy;
import se.swedenconnect.oidcfed.commons.configuration.PolicyParameterFormats;
import se.swedenconnect.oidcfed.commons.data.oidcfed.builders.TrustMarkIssuersBuilder;
import se.swedenconnect.oidcfed.commons.data.oidcfed.builders.TrustMarkOwnersBuilder;
import se.swedenconnect.oidcfed.commons.process.metadata.MetadataPolicySerializer;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyOperatorFactory;
import se.swedenconnect.oidcfed.commons.process.metadata.impl.DefaultPolicyOperatorFactory;
import se.swedenconnect.oidcfed.commons.process.metadata.impl.StandardMetadataPolicySerializer;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.RegexpPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.SkipSubordinatesPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.SubsetOfPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.ValuePolicyOperator;
import se.swedenconnect.oidcfed.commons.testdata.TestCredentials;
import se.swedenconnect.oidcfed.commons.utils.OidcUtils;

/**
 * Tests for EntityStatement
 */
@Slf4j
class EntityStatementTest {

  static PolicyOperatorFactory policyOperatorFactory;
  static MetadataPolicySerializer serializer;

  @BeforeAll
  static void init() {
    policyOperatorFactory = DefaultPolicyOperatorFactory.getInstance();
    serializer = new StandardMetadataPolicySerializer(policyOperatorFactory,
      Arrays.stream(PolicyParameterFormats.values())
        .collect(
          Collectors.toMap(PolicyParameterFormats::getParameterName, PolicyParameterFormats::toMetadataParameter))
    );
  }


  @Test
  void builderTest() throws Exception{

    EntityStatement entityStatement = EntityStatement.builder()
      .issuer("issuer")
      .subject("subject")
      .expriationTime(Date.from(Instant.now().plusSeconds(180)))
      .issueTime(new Date())
      .definedParams(EntityStatementDefinedParams.builder()
        .authorityHints(List.of("hint1", "hint2"))
        .constraints(ConstraintsClaim.builder()
          .allowedLeafEntityTypes(List.of("openid_relying_party", "openid_provider"))
          .maxPathLength(2)
          .namingConstraints(NamingConstraints.builder()
            .excluded(List.of("https://example.com/excluded"))
            .permitted(List.of("https://example.com/permitted"))
            .build())
          .build())
        .subjectDataPublication(SubjectDataPublication.builder()
          .entityConfigurationPublicationType(SubjectDataPublication.PUBLICATION_TYPE_NONE)
          .build(), true)
        .addCriticalClaim("other_critical_claim")
        .jwkSet(getJwkSet(TestCredentials.p256Credential.getCertificate()))
        .metadata(EntityMetadataInfoClaim.builder()
          .opMetadataObject(OpMetadata.builder()
            .issuer("Issuer")
            .organizationName(LanguageObject.builder(String.class)
              .defaultValue("DIGG")
              .langValue("sv", "Svenska")
              .langValue("en", "English")
              .langValue("es", "Español")
              .build())
            .jwkSet(getJwkSet(TestCredentials.p521Credential.getCertificate()))
            .signedJwksUri("http://example.com/jwkset")
            .oidcSeDiscoUserMessageSupported(true)
            .oidcSeDiscoAuthnProviderSupported(true)
            .oidcSeDiscoUserMessageSupportedMimeTypes(List.of("text/plain"))
            .build().toJsonObject())
          .oidcRelyingPartyMetadataObject(RelyingPartyMetadata.builder()
            .organizationName(LanguageObject.builder(String.class)
              .defaultValue("DIGG")
              .langValue("sv", "Myndigheten för digital förvaltning")
              .langValue("en", "Government Agency for Digital Government")
              .build())
            .build().toJsonObject())
          .build())
        .addPolicyLanguageCriticalClaim(RegexpPolicyOperator.OPERATOR_NAME)
        .addPolicyLanguageCriticalClaim(ValuePolicyOperator.OPERATOR_NAME)
        .addPolicyLanguageCriticalClaim(SkipSubordinatesPolicyOperator.OPERATOR_NAME)
        .metadataPolicy(EntityMetadataInfoClaim.builder()
          .opMetadataObject(serializer.toJsonObject(EntityTypeMetadataPolicy.builder()
            .addMetadataParameterPolicy(MetadataParameterPolicy.builder(PolicyParameterFormats.issuer.toMetadataParameter())
              .add(RegexpPolicyOperator.OPERATOR_NAME, OidcUtils.URI_REGEXP)
              .build())
            .addMetadataParameterPolicy(MetadataParameterPolicy.builder(PolicyParameterFormats.acr_values_supported.toMetadataParameter())
              .add(SubsetOfPolicyOperator.OPERATOR_NAME,
                List.of("http://id.elegnamnden.se/loa/1.0/loa3", "http://id.elegnamnden.se/loa/1.0/loa4",
                "http://id.elegnamnden.se/loa/1.0/eidas-sub", "http://id.elegnamnden.se/loa/1.0/eidas-nf-sub",
                "http://id.elegnamnden.se/loa/1.0/eidas-high", "http://id.elegnamnden.se/loa/1.0/eidas-nf-high"))
              .add(RegexpPolicyOperator.OPERATOR_NAME, List.of(OidcUtils.URI_REGEXP, "^.{3,}$"))
              .build())
            .build()))
          .build())
        .sourceEndpoint("http://example.com/source")
        .trustMarkIssuers(TrustMarkIssuersBuilder.getInstance()
          .trustMark("https://example.com/tm1", List.of("https://example.com/issuer1"))
          .trustMark("https://example.com/tm2", List.of("https://example.com/issuer1", "https://example.com/issuer2"))
          .build())
        .trustMarks(List.of(
          TrustMarkClaim.builder()
            .id("https://example.com/tm1")
            .trustMark(TrustMark.builder()
              .id("https://example.com/tm1")
              .subject("https://example.com/subject")
              .issueTime(new Date())
              .issuer("https://example.com/trust_mark_issuer")
              .build(TestCredentials.p256JwtCredential, null).getSignedJWT().serialize())
            .build(),
          TrustMarkClaim.builder()
            .id("https://example.com/tm2")
            .trustMark("Signed trust mark JWT")
            .build()))
        .trustMarkOwners(TrustMarkOwnersBuilder.getInstance()
          .trustMark("https://example.com/tm1", "https://example.com/owner1", getJwkSet(TestCredentials.p256Credential.getCertificate()))
          .trustMark("https://example.com/tm2", "https://example.com/owner2", getJwkSet(TestCredentials.p256Credential.getCertificate()))
          .build())
        .build())
      .build(TestCredentials.p256JwtCredential, null);

    log.info("Entity Statement:\n{}", entityStatement.getSignedJWT().serialize());
    JWSHeader entityStatementHeader = entityStatement.getSignedJWT().getHeader();
    log.info("Header: \n{}", OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(
      entityStatementHeader.toJSONObject()));
    assertEquals("entity-statement+jwt", entityStatementHeader.getType().getType());

    Map<String, Object> entityStatementPayloadJsonObject = entityStatement.getSignedJWT().getJWTClaimsSet().toJSONObject();
    String entityStatementPayloadJson = OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(entityStatementPayloadJsonObject);
    log.info("Entity statement payload:\n{}", entityStatementPayloadJson);


    // Parse the statement back to Java
    EntityStatement parsedEntityStatement = new EntityStatement(entityStatement.getSignedJWT());
    Map<String, Object> opMetadataObject = parsedEntityStatement.getMetadata().getOpMetadataObject();
    OpMetadata parsedOpMetadata = OpMetadata.getJsonSerializer().parse(opMetadataObject);

    log.info("Parsed OP metadata:\n{}", parsedOpMetadata.toJson(true));

  }

  private JWKSet getJwkSet(X509Certificate... certificate) {

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