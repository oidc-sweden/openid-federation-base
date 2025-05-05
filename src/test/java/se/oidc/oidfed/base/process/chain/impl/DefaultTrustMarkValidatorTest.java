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
package se.oidc.oidfed.base.process.chain.impl;

import com.nimbusds.jose.jwk.JWKSet;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.oidc.oidfed.base.configuration.PolicyParameterFormats;
import se.oidc.oidfed.base.data.federation.EntityStatement;
import se.oidc.oidfed.base.data.federation.TrustMark;
import se.oidc.oidfed.base.data.federation.TrustMarkDelegation;
import se.oidc.oidfed.base.data.federation.TrustMarkOwner;
import se.oidc.oidfed.base.process.chain.FederationChainValidator;
import se.oidc.oidfed.base.process.chain.TrustMarkValidator;
import se.oidc.oidfed.base.process.metadata.MetadataPolicySerializer;
import se.oidc.oidfed.base.process.metadata.PolicyOperatorFactory;
import se.oidc.oidfed.base.process.metadata.impl.DefaultPolicyOperatorFactory;
import se.oidc.oidfed.base.process.metadata.impl.StandardMetadataPolicySerializer;
import se.oidc.oidfed.base.testdata.TestCredentials;
import se.oidc.oidfed.base.testdata.TestEntityStatements;
import se.oidc.oidfed.base.utils.JWKUtils;
import se.oidc.oidfed.base.utils.OidcUtils;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test for trust mark validator
 */
@Slf4j
class DefaultTrustMarkValidatorTest {

  static PolicyOperatorFactory policyOperatorFactory;
  static MetadataPolicySerializer serializer;

  static FederationChainValidator federationChainValidator;

  @BeforeAll
  static void init() {

    final JWKSet t1JwkSet = TestCredentials.getJwkSet(TestCredentials.ta1.getCertificate());

    policyOperatorFactory = DefaultPolicyOperatorFactory.getInstance();
    serializer = new StandardMetadataPolicySerializer(policyOperatorFactory,
        Arrays.stream(PolicyParameterFormats.values())
            .collect(
                Collectors.toMap(PolicyParameterFormats::getParameterName, PolicyParameterFormats::toMetadataParameter))
    );

    federationChainValidator = new DefaultFederationChainValidator(t1JwkSet, serializer);

  }

  @Test
  void trustMarkTests() throws Exception {

    this.performTrustMarkTest("Default success test",
        List.of(TrustMark.builder()
            .trustMarkId("https://example.com/trustMark-1")
            .issuer("https://example.com/ie2")
            .subject("https://example.com/op1")
            .issueTime(new Date())
            .expriationTime(Date.from(Instant.now().plusSeconds(120)))
            .delegation(TrustMarkDelegation.builder()
                .trustMarkId("https://example.com/trustMark-1")
                .issuer("https://example.com/trust-mark-owner")
                .subject("https://example.com/ie2")
                .issueTime(new Date())
                .expriationTime(Date.from(Instant.now().plusSeconds(3600)))
                .build(TestCredentials.p256JwtCredential, null).getSignedJWT())
            .build(TestCredentials.ie2Sig, null)),
        "op1",
        List.of(
            TestEntityStatements.ta1_conf()
                .trustMarkIssuersMap(
                    Collections.singletonMap("https://example.com/trustMark-1", List.of("https://example.com/ie2")))
                .trustMarkOwnerMap(
                    Collections.singletonMap("https://example.com/trustMark-1", new TrustMarkOwner(
                        "https://example.com/trust-mark-owner",
                        new JWKSet(List.of(
                            JWKUtils.getJwkWithKid(TestCredentials.p256Credential.getCertificate(), "test_p256",
                                false)))
                    ))
                ),
            TestEntityStatements.ta1_ie1_statement(),
            TestEntityStatements.ie1_ie2_statement(),
            TestEntityStatements.ie2_ie2_configuration()
        ),
        List.of("https://example.com/trustMark-1"),
        true, null
    );


/*    performTrustMarkTest("Default reduced TM Issuer chain",
      List.of(TrustMark.builder()
          .id("https://example.com/trustMark-1")
          .issuer("https://example.com/ie2")
          .subject("https://example.com/op1")
          .issueTime(new Date())
          .expriationTime(Date.from(Instant.now().plusSeconds(120)))
          .delegation(TrustMarkDelegation.builder()
            .id("https://example.com/trustMark-1")
            .issuer("https://example.com/trust-mark-owner")
            .subject("https://example.com/ie2")
            .issueTime(new Date())
            .expriationTime(Date.from(Instant.now().plusSeconds(3600)))
            .build(TestCredentials.p256JwtCredential, null).getSignedJWT())
        .build(TestCredentials.ie2Sig, null)),
      "op1",
      List.of(
        TestEntityStatements.ta1_conf()
          .trustMarkIssuersMap(
            Collections.singletonMap("https://example.com/trustMark-1", List.of("https://example.com/ie2")))
          .trustMarkOwnerMap(
            Collections.singletonMap("https://example.com/trustMark-1", new TrustMarkOwner(
              "https://example.com/trust-mark-owner",
              new JWKSet(List.of(
                JWKUtils.getJwkWithKid(TestCredentials.p256Credential.getCertificate(), "test_p256", false)))
            ))
          ),
        TestEntityStatements.ta1_ie1_statement(),
        TestEntityStatements.ie1_ie2_statement()
          .metadata(EntityMetadataInfoClaim.builder()
            .federationEntityMetadataObject(FederationEndpointMetadata.builder()
              .federationFetchEndpoint("https://example.com/fetchEndpoint")
              .federationListEndpoint("https://example.com/listEndpoint")
              .federationTrustMarkEndpoint("https://example.com/trustMarkEndpoint")
              .build().toJsonObject())
            .build())
          .noSubjectDataStorage(true)
      ),
      List.of("https://example.com/trustMark-1"),
      true, null
      );*/

    this.performTrustMarkTest("Bad Trust Mark delegation",
        List.of(TrustMark.builder()
            .trustMarkId("https://example.com/trustMark-1")
            .issuer("https://example.com/ie2")
            .subject("https://example.com/op1")
            .issueTime(new Date())
            .expriationTime(Date.from(Instant.now().plusSeconds(120)))
            .delegation(TrustMarkDelegation.builder()
                .trustMarkId("https://example.com/trustMark-1")
                .issuer("https://example.com/trust-mark-owner")
                .subject("https://example.com/ie1")
                .issueTime(new Date())
                .expriationTime(Date.from(Instant.now().plusSeconds(3600)))
                .build(TestCredentials.p256JwtCredential, null).getSignedJWT())
            .build(TestCredentials.ie2Sig, null)),
        "op1",
        List.of(
            TestEntityStatements.ta1_conf()
                .trustMarkIssuersMap(
                    Collections.singletonMap("https://example.com/trustMark-1", List.of("https://example.com/ie2")))
                .trustMarkOwnerMap(
                    Collections.singletonMap("https://example.com/trustMark-1", new TrustMarkOwner(
                        "https://example.com/trust-mark-owner",
                        new JWKSet(List.of(
                            JWKUtils.getJwkWithKid(TestCredentials.p256Credential.getCertificate(), "test_p256",
                                false)))
                    ))
                ),
            TestEntityStatements.ta1_ie1_statement(),
            TestEntityStatements.ie1_ie2_statement(),
            TestEntityStatements.ie2_ie2_configuration()
            //        TestEntityStatements.ie1_ie2_statement()
            //          .metadata(EntityMetadataInfoClaim.builder()
            //            .federationEntityMetadataObject(FederationEndpointMetadata.builder()
            //              .federationFetchEndpoint("https://example.com/fetchEndpoint")
            //              .federationListEndpoint("https://example.com/listEndpoint")
            //              .federationTrustMarkEndpoint("https://example.com/trustMarkEndpoint")
            //              .build().toJsonObject())
            //            .build())
            //          .noSubjectDataStorage(true)
        ),
        List.of(),
        true, null
    );

    this.performTrustMarkTest("Revoked Trust Mark",
        List.of(TrustMark.builder()
            .trustMarkId("https://example.com/trustMark-1")
            .issuer("https://example.com/ie2")
            .subject("https://example.com/op1")
            .issueTime(new Date())
            .expriationTime(Date.from(Instant.now().plusSeconds(120)))
            .build(TestCredentials.ie2Sig, null)),
        "op1",
        List.of(
            TestEntityStatements.ta1_conf()
                .trustMarkIssuersMap(
                    Collections.singletonMap("https://example.com/trustMark-1", List.of("https://example.com/ie2"))),
            TestEntityStatements.ta1_ie1_statement(),
            TestEntityStatements.ie1_ie2_statement(),
            TestEntityStatements.ie2_ie2_configuration()
        ),
        List.of(),
        false, null
    );

    this.performTrustMarkTest("Wrong trust mark signing key",
        List.of(TrustMark.builder()
            .trustMarkId("https://example.com/trustMark-1")
            .issuer("https://example.com/ie2")
            .subject("https://example.com/op1")
            .issueTime(new Date())
            .expriationTime(Date.from(Instant.now().plusSeconds(120)))
            .build(TestCredentials.rsa3072JwtCredential, null)),
        "op1",
        List.of(
            TestEntityStatements.ta1_conf()
                .trustMarkIssuersMap(
                    Collections.singletonMap("https://example.com/trustMark-1", List.of("https://example.com/ie2"))),
            TestEntityStatements.ta1_ie1_statement(),
            TestEntityStatements.ie1_ie2_statement(),
            TestEntityStatements.ie2_ie2_configuration()
        ),
        List.of(),
        true, null
    );
  }

  void performTrustMarkTest(final String message, final List<TrustMark> trustMarks, final String subjectId,
      final List<TestEntityStatements.EsData.EsDataBuilder> builderChain, final List<String> expected,
      final boolean status,
      final Class<? extends Exception> exceptionClass) throws Exception {
    log.info("Entity Statement chain validation test: {}", message);

    final String subject = "https://example.com/" + subjectId;
    final String trustAnchorName = "https://example.com/ta1";

    if (exceptionClass != null) {
      final Exception exception = assertThrows(exceptionClass, () -> {

        final List<EntityStatement> tmiChain = builderChain.stream()
            .map(esDataBuilder -> TestEntityStatements.getEntityStatement(esDataBuilder.build()))
            .toList();
        final TrustMarkValidator trustMarkValidator = this.getTrustMarkValidator(tmiChain, status);
        trustMarkValidator.validateTrustMarks(trustMarks, subject, trustAnchorName);

      });
      log.info("Caught expected exception {} with message: {}\n", exception.getClass().getSimpleName(),
          exception.getMessage());
      return;
    }

    final List<EntityStatement> trustMarkIssuerChain = builderChain.stream()
        .map(esDataBuilder -> TestEntityStatements.getEntityStatement(esDataBuilder.build()))
        .toList();
    log.info("Validated chain");
    for (final EntityStatement entityStatement : trustMarkIssuerChain) {
      this.logEntityStatementInfo(entityStatement);
    }
    final TrustMarkValidator trustMarkValidator = this.getTrustMarkValidator(trustMarkIssuerChain, status);
    final List<TrustMark> validatedTrustMarks =
        trustMarkValidator.validateTrustMarks(trustMarks, subject, trustAnchorName);
    for (final String trustMarkId : expected) {
      assertTrue(validatedTrustMarks.stream().anyMatch(trustMark -> trustMarkId.equals(trustMark.getTrustMarkId())));
    }
    assertEquals(expected.size(), validatedTrustMarks.size());
    log.info("Found expected valid trust marks: {}\n", expected);
  }

  TrustMarkValidator getTrustMarkValidator(final List<EntityStatement> chain, final boolean status) {

    return new DefaultTrustMarkValidator(
        (entityIdentifier, trustAnchor, trustAnchorFirst) -> {
          if (trustAnchorFirst) {
            return chain;
          }
          final List<EntityStatement> leafFirstChain = new ArrayList<>(chain);
          Collections.reverse(leafFirstChain);
          return leafFirstChain;
        },
        (trustMarkId, subject, issuer) -> status, federationChainValidator
    );
  }

  private void logEntityStatementInfo(final EntityStatement entityStatement) throws Exception {
    log.info("Entity Statement issued by: {} - for: {}\n{}", entityStatement.getIssuer(), entityStatement.getSubject(),
        OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
            .writeValueAsString(entityStatement.getSignedJWT().getJWTClaimsSet().toJSONObject()));
  }

}
