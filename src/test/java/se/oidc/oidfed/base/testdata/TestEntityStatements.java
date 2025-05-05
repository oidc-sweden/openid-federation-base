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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.oidc.oidfed.base.configuration.PolicyParameterFormats;
import se.oidc.oidfed.base.data.metadata.policy.EntityTypeMetadataPolicy;
import se.oidc.oidfed.base.data.metadata.policy.MetadataParameterPolicy;
import se.oidc.oidfed.base.data.metadata.policy.SkipSubMetadataParameterPolicy;
import se.oidc.oidfed.base.data.federation.ConstraintsClaim;
import se.oidc.oidfed.base.data.federation.EntityMetadataInfoClaim;
import se.oidc.oidfed.base.data.federation.EntityStatement;
import se.oidc.oidfed.base.data.federation.EntityStatementDefinedParams;
import se.oidc.oidfed.base.data.federation.TrustMark;
import se.oidc.oidfed.base.data.federation.TrustMarkClaim;
import se.oidc.oidfed.base.data.federation.TrustMarkOwner;
import se.oidc.oidfed.base.process.metadata.PolicyProcessingException;
import se.oidc.oidfed.base.process.metadata.PolicyTranslationException;
import se.oidc.oidfed.base.process.metadata.impl.SkipSubordniatePolicyOperatorFactory;
import se.oidc.oidfed.base.process.metadata.impl.StandardMetadataPolicySerializer;
import se.oidc.oidfed.base.process.metadata.policyoperators.SubsetOfPolicyOperator;
import se.oidc.oidfed.base.process.metadata.policyoperators.SupersetOfPolicyOperator;
import se.oidc.oidfed.base.security.JWTSigningCredential;
import se.oidc.oidfed.base.utils.JWKUtils;
import se.swedenconnect.security.credential.PkiCredential;

import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class TestEntityStatements {

  static SkipSubordniatePolicyOperatorFactory policyOperatorFactory;
  static StandardMetadataPolicySerializer policySerializer;

  public static EsData.EsDataBuilder ta1_conf() {
    return EsData.builder()
        .subjName("ta1")
        .issuerName("ta1")
        .subjCredential(TestCredentials.ta1)
        .sigCredential(TestCredentials.ta1Sig)
        .trustMarkIssuerClaim(true)
        .trustMark(false);
  }

  public static EsData.EsDataBuilder ta1_ie1_statement() throws PolicyTranslationException, PolicyProcessingException {
    return EsData.builder()
        .subjName("ie1")
        .issuerName("ta1")
        .subjCredential(TestCredentials.ie1)
        .sigCredential(TestCredentials.ta1Sig)
        .trustMark(false)
        .policy(EntityMetadataInfoClaim.builder()
            .opMetadataObject(policySerializer.toJsonObject(EntityTypeMetadataPolicy.builder()
                .addMetadataParameterPolicy(
                    SkipSubMetadataParameterPolicy.builder(
                            PolicyParameterFormats.scopes_supported.toMetadataParameter())
                        .add(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("openid", "custom1"))
                        .skipSubordinates(true)
                        .build())
                .addMetadataParameterPolicy(
                    MetadataParameterPolicy.builder(PolicyParameterFormats.claims_supported.toMetadataParameter())
                        .add(SupersetOfPolicyOperator.OPERATOR_NAME, List.of("claim1", "claim2"))
                        .build())
                .build()))
            .oidcRelyingPartyMetadataObject(policySerializer.toJsonObject(EntityTypeMetadataPolicy.builder()
                .addMetadataParameterPolicy(
                    MetadataParameterPolicy.builder(PolicyParameterFormats.response_types.toMetadataParameter())
                        .add(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("code"))
                        .build())
                .build()))
            .build());
  }

  public static EsData.EsDataBuilder ie1_ie2_statement() {
    return EsData.builder()
        .subjName("ie2")
        .issuerName("ie1")
        .subjCredential(TestCredentials.ie2)
        .sigCredential(TestCredentials.ie1Sig)
        .trustMark(false);
  }

  public static EsData.EsDataBuilder ie2_ie2_configuration() throws JsonProcessingException {
    return EsData.builder()
        .subjName("ie2")
        .issuerName("ie2")
        .subjCredential(TestCredentials.ie2)
        .sigCredential(TestCredentials.ie2Sig)
        .authorityHints(List.of("ie1", "ta1"))
        .metadata(EntityMetadataInfoClaim.builder()
            .federationEntityMetadataObject(TestMetadata.federationEntityMetadata)
            .build())
        .trustMark(false);
  }

  public static EsData.EsDataBuilder ie2_op1() {
    return EsData.builder()
        .subjName("op1")
        .issuerName("ie2")
        .subjCredential(TestCredentials.op1)
        .sigCredential(TestCredentials.ie2Sig)
        .constraintsClaim(ConstraintsClaim.builder()
            .maxPathLength(0)
            .build())
        .trustMark(false);
  }

  public static EsData.EsDataBuilder op1_conf() throws JsonProcessingException {
    return EsData.builder()
        .subjName("op1")
        .issuerName("op1")
        .subjCredential(TestCredentials.op1)
        .sigCredential(TestCredentials.op1Sig)
        .trustMark(true)
        .authorityHints(List.of("ie1", "ie2"))
        .metadata(EntityMetadataInfoClaim.builder()
            .opMetadataObject(TestMetadata.opMetadata_claims123)
            .build());
  }

  public static EsData.EsDataBuilder ta1_op1_direct() throws JsonProcessingException {
    return EsData.builder()
        .subjName("op1")
        .issuerName("ta1")
        .subjCredential(TestCredentials.op1)
        .sigCredential(TestCredentials.ta1Sig)
        .trustMark(true)
        .noSubjectDataStorage(true)
        .metadata(EntityMetadataInfoClaim.builder()
            .opMetadataObject(TestMetadata.opMetadata_claims123)
            .build());
  }

  public static EsData.EsDataBuilder ie2_rp1_metadata() throws JsonProcessingException {
    return EsData.builder()
        .subjName("rp1")
        .issuerName("ie2")
        .subjCredential(TestCredentials.rp1)
        .sigCredential(TestCredentials.ie2Sig)
        .noSubjectDataStorage(true)
        .trustMark(true)
        .metadata(EntityMetadataInfoClaim.builder()
            .oidcRelyingPartyMetadataObject(TestMetadata.rpMetadata_rt)
            .build());
  }

  static {
    try {
      policyOperatorFactory = SkipSubordniatePolicyOperatorFactory.getInstance();
      policySerializer = new StandardMetadataPolicySerializer(policyOperatorFactory,
          Arrays.stream(PolicyParameterFormats.values())
              .collect(
                  Collectors.toMap(PolicyParameterFormats::getParameterName,
                      PolicyParameterFormats::toMetadataParameter))
      );
    }
    catch (final Exception ex) {
      throw new RuntimeException(ex);
    }
  }

  public static EntityStatement getEntityStatement(final EsData esData) {

    try {
      final EntityStatement.EntityStatementBuilder esBuilder = EntityStatement.builder();
      final EntityStatementDefinedParams.EntityStatementDefinedParamsBuilder esParamsBuilder =
          EntityStatementDefinedParams.builder();

      esParamsBuilder
          .jwkSet(JWKUtils.jwksBuilder()
              .addKey(esData.subjCredential.getCertificate(), "test_" + esData.subjName).build())
          .authorityHints(esData.getAuthorityHints())
          .metadata(esData.getMetadata())
          .metadataPolicy(esData.getPolicy())
          .constraints(esData.getConstraintsClaim());

      if (esData.getCriticalClaims() != null) {
        esData.getCriticalClaims().forEach(esParamsBuilder::addCriticalClaim);
      }
      if (esData.getPolicyCriticalClaims() != null) {
        esData.getPolicyCriticalClaims().forEach(esParamsBuilder::addPolicyLanguageCriticalClaim);
      }
      if (esData.isTrustMark()) {
        esParamsBuilder
            .trustMarks(List.of(
                TrustMarkClaim.builder()
                    .trustMark(TrustMark.builder()
                        .trustMarkId("https://example.com/tm1")
                        .subject("https://example.com/subject")
                        .issueTime(new Date())
                        .issuer("https://example.com/trust_mark_issuer")
                        .build(TestCredentials.p256JwtCredential, null).getSignedJWT().serialize())
                    .build()));
      }
      if (esData.isTrustMarkIssuerClaim()) {
        esParamsBuilder
            .trustMarkIssuers(
                Collections.singletonMap("https://example.com/tm1", List.of("https://example.com/trust_mark_issuer")));
      }
      if (esData.getTrustMarkIssuersMap() != null) {
        esParamsBuilder
            .trustMarkIssuers(esData.trustMarkIssuersMap);
      }
      if (esData.trustMarkOwnerMap != null) {
        esParamsBuilder
            .trustMarkOwners(esData.getTrustMarkOwnerMap());
      }

      if (esData.noSubjectDataStorage) {
        esParamsBuilder.subjectEntityConfigurationLocation("https://example.com/subject-entity-configuration", true);
      }

      if (esData.getAuthorityHints() != null) {
        esParamsBuilder.authorityHints(
            esData.getAuthorityHints().stream()
                .map(s -> "https://example.com/" + s)
                .toList());
      }

      return esBuilder
          .subject("https://example.com/" + esData.getSubjName())
          .issuer("https://example.com/" + esData.getIssuerName())
          .issueTime(new Date())
          .expriationTime(Date.from(Instant.now().plusSeconds(600)))
          .definedParams(esParamsBuilder.build())
          .build(esData.getSigCredential(), null);

    }
    catch (final NoSuchAlgorithmException | JOSEException | JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }

  @Data
  @AllArgsConstructor
  @NoArgsConstructor
  @Builder
  public static class EsData {

    private String subjName;
    private String issuerName;
    private PkiCredential subjCredential;
    private JWTSigningCredential sigCredential;
    private List<String> authorityHints;
    private EntityMetadataInfoClaim metadata;
    private EntityMetadataInfoClaim policy;
    private ConstraintsClaim constraintsClaim;
    private List<String> criticalClaims;
    private List<String> policyCriticalClaims;
    private boolean trustMark;
    private boolean trustMarkIssuerClaim;
    private Map<String, List<String>> trustMarkIssuersMap;
    private boolean noSubjectDataStorage;
    private Map<String, TrustMarkOwner> trustMarkOwnerMap;
  }

}
