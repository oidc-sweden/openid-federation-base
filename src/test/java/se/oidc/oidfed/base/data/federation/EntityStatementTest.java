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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.oidc.oidfed.base.configuration.PolicyParameterFormats;
import se.oidc.oidfed.base.data.metadata.policy.EntityTypeMetadataPolicy;
import se.oidc.oidfed.base.data.metadata.policy.MetadataParameterPolicy;
import se.oidc.oidfed.base.data.federation.builders.TrustMarkIssuersBuilder;
import se.oidc.oidfed.base.data.federation.builders.TrustMarkOwnersBuilder;
import se.oidc.oidfed.base.process.metadata.MetadataPolicySerializer;
import se.oidc.oidfed.base.process.metadata.PolicyOperatorFactory;
import se.oidc.oidfed.base.process.metadata.impl.DefaultPolicyOperatorFactory;
import se.oidc.oidfed.base.process.metadata.impl.StandardMetadataPolicySerializer;
import se.oidc.oidfed.base.process.metadata.policyoperators.RegexpPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.SkipSubordinatesPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.SubsetOfPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.ValuePolicyOperator;
import se.oidc.oidfed.base.testdata.TestCredentials;
import se.oidc.oidfed.base.testdata.TestMetadata;
import se.oidc.oidfed.base.utils.OidcUtils;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
  void builderTest() throws Exception {

    final EntityStatement entityStatement = EntityStatement.builder()
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
            .subjectEntityConfigurationLocation("https://example.com/entity-configuration", true)
            .addCriticalClaim("other_critical_claim")
            .jwkSet(this.getJwkSet(TestCredentials.p256Credential.getCertificate()))
            .metadata(EntityMetadataInfoClaim.builder()
                .opMetadataObject(TestMetadata.opMetadata)
                .oidcRelyingPartyMetadataObject(TestMetadata.rpMetadata)
                .build())
            .addPolicyLanguageCriticalClaim(RegexpPolicyOperator.OPERATOR_NAME)
            .addPolicyLanguageCriticalClaim(ValuePolicyOperator.OPERATOR_NAME)
            .addPolicyLanguageCriticalClaim(SkipSubordinatesPolicyOperator.OPERATOR_NAME)
            .metadataPolicy(EntityMetadataInfoClaim.builder()
                .opMetadataObject(serializer.toJsonObject(EntityTypeMetadataPolicy.builder()
                    .addMetadataParameterPolicy(
                        MetadataParameterPolicy.builder(PolicyParameterFormats.issuer.toMetadataParameter())
                            .add(RegexpPolicyOperator.OPERATOR_NAME, OidcUtils.URI_REGEXP)
                            .build())
                    .addMetadataParameterPolicy(MetadataParameterPolicy.builder(
                            PolicyParameterFormats.acr_values_supported.toMetadataParameter())
                        .add(SubsetOfPolicyOperator.OPERATOR_NAME,
                            List.of("http://id.elegnamnden.se/loa/1.0/loa3", "http://id.elegnamnden.se/loa/1.0/loa4",
                                "http://id.elegnamnden.se/loa/1.0/eidas-sub",
                                "http://id.elegnamnden.se/loa/1.0/eidas-nf-sub",
                                "http://id.elegnamnden.se/loa/1.0/eidas-high",
                                "http://id.elegnamnden.se/loa/1.0/eidas-nf-high"))
                        .add(RegexpPolicyOperator.OPERATOR_NAME, List.of(OidcUtils.URI_REGEXP, "^.{3,}$"))
                        .build())
                    .build()))
                .build())
            .sourceEndpoint("http://example.com/source")
            .trustMarkIssuers(TrustMarkIssuersBuilder.getInstance()
                .trustMark("https://example.com/tm1", List.of("https://example.com/issuer1"))
                .trustMark("https://example.com/tm2",
                    List.of("https://example.com/issuer1", "https://example.com/issuer2"))
                .build())
            .trustMarks(List.of(
                TrustMarkClaim.builder()
                    .trustMarkId("https://example.com/tm1")
                    .trustMark(TrustMark.builder()
                        .trustMarkId("https://example.com/tm1")
                        .subject("https://example.com/subject")
                        .issueTime(new Date())
                        .issuer("https://example.com/trust_mark_issuer")
                        .build(TestCredentials.p256JwtCredential, null).getSignedJWT().serialize())
                    .build(),
                TrustMarkClaim.builder()
                    .trustMarkId("https://example.com/tm2")
                    .trustMark("Signed trust mark JWT")
                    .build()))
            .trustMarkOwners(TrustMarkOwnersBuilder.getInstance()
                .trustMark("https://example.com/tm1", "https://example.com/owner1",
                    this.getJwkSet(TestCredentials.p256Credential.getCertificate()))
                .trustMark("https://example.com/tm2", "https://example.com/owner2",
                    this.getJwkSet(TestCredentials.p256Credential.getCertificate()))
                .build())
            .build())
        .build(TestCredentials.p256JwtCredential, null);

    log.info("Entity Statement:\n{}", entityStatement.getSignedJWT().serialize());
    final JWSHeader entityStatementHeader = entityStatement.getSignedJWT().getHeader();
    log.info("Header: \n{}", OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(
        entityStatementHeader.toJSONObject()));
    assertEquals("entity-statement+jwt", entityStatementHeader.getType().getType());

    final Map<String, Object> entityStatementPayloadJsonObject =
        entityStatement.getSignedJWT().getJWTClaimsSet().toJSONObject();
    final String entityStatementPayloadJson =
        OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(entityStatementPayloadJsonObject);
    log.info("Entity statement payload:\n{}", entityStatementPayloadJson);

    // Parse the statement back to Java
    final EntityStatement parsedEntityStatement = new EntityStatement(entityStatement.getSignedJWT());
    final Map<String, Object> opMetadataObject = parsedEntityStatement.getMetadata().getOpMetadataObject();

    log.info("Parsed OP metadata:\n{}", OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(opMetadataObject));

  }

  private JWKSet getJwkSet(final X509Certificate... certificate) {

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
