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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import jakarta.annotation.Nonnull;
import lombok.extern.slf4j.Slf4j;
import se.oidc.oidfed.base.data.federation.ConstraintsClaim;
import se.oidc.oidfed.base.data.federation.EntityMetadataInfoClaim;
import se.oidc.oidfed.base.data.federation.EntityStatement;
import se.oidc.oidfed.base.data.federation.NamingConstraints;
import se.oidc.oidfed.base.data.federation.TrustMarkClaim;
import se.oidc.oidfed.base.data.metadata.policy.EntityTypeMetadataPolicy;
import se.oidc.oidfed.base.data.metadata.policy.MetadataParameterPolicy;
import se.oidc.oidfed.base.process.chain.ChainValidationException;
import se.oidc.oidfed.base.process.chain.ChainValidationResult;
import se.oidc.oidfed.base.process.chain.FederationChainValidator;
import se.oidc.oidfed.base.process.metadata.MetadataPolicyProcessor;
import se.oidc.oidfed.base.process.metadata.MetadataPolicySerializer;
import se.oidc.oidfed.base.process.metadata.PolicyMergeException;
import se.oidc.oidfed.base.process.metadata.PolicyProcessingException;
import se.oidc.oidfed.base.process.metadata.PolicyTranslationException;
import se.oidc.oidfed.base.utils.OidcUtils;

import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Entity Statement chain validation implementation
 *
 * <p>
 * The definition of constraints is ambiguous. This implementation make two interpretations. allowed_leaf_entity_types
 * will ignore any presence of "federation_entity" as this type can be used by any role. Naming constraints will be
 * applied as URL prefix. Anything that matches the beginning of this URL prefix, matches the constraint (permitted and
 * excluded).
 * </p>
 * <p>
 * Also. No attempt to compare constraints is made. Instead. All constraints are individually processed against their
 * respective sub-path.
 * </p>
 */
@Slf4j
public class DefaultFederationChainValidator implements FederationChainValidator {

  private final JWKSet trustedKeys;
  private final MetadataPolicySerializer metadataPolicySerializer;
  private final MetadataPolicyProcessor metadataPolicyProcessor;

  private final List<String> supportedCriticalClaims =
      List.of(EntityStatement.SUBJECT_ENTITY_CONFIGURATION_LOCATION_CLAIM_NAME);

  /**
   * Constructor
   *
   * @param trustedKeys the keys trusted to verify Trust Anchor entity configuration statements
   * @param metadataPolicySerializer serializer for parsing metadata policy data
   */
  public DefaultFederationChainValidator(final JWKSet trustedKeys,
      final MetadataPolicySerializer metadataPolicySerializer) {
    this.trustedKeys = trustedKeys;
    this.metadataPolicySerializer = metadataPolicySerializer;
    this.metadataPolicyProcessor = new MetadataPolicyProcessor();
  }

  /** {@inheritDoc} */
  @Override
  public ChainValidationResult validate(@Nonnull final List<EntityStatement> unorderedChain)
      throws ChainValidationException {

    final List<EntityStatement> chain = this.orderChain(unorderedChain);

    // Check that chain has at least length = 2
    if (chain.size() < 3) {
      throw new ChainValidationException("Chain does not include at least two statements");
    }
    log.debug("Validating chain of length {}", chain.size());

    if (log.isTraceEnabled()) {
      log.trace("Chain to validate:");
      for (final EntityStatement entityStatement : chain) {
        try {
          log.trace("Entity Statement issued by: {} - for: {}\n{}", entityStatement.getIssuer(),
              entityStatement.getSubject(),
              OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
                  .writeValueAsString(entityStatement.getSignedJWT().getJWTClaimsSet().toJSONObject()));
        }
        catch (final JsonProcessingException | ParseException e) {
          throw new RuntimeException(e);
        }
      }
    }

    // Check signatures
    this.checkSignatures(chain);
    log.debug("All signatures of the chain successfully validated");

    // Check constraints
    this.checkConstraints(chain);
    log.debug("Constraints successfully validated");

    // Check critical claims
    this.checkCriticalClaims(chain);
    log.debug("No unrecognized critical claims");

    // Metadata policy merge
    final Map<String, EntityTypeMetadataPolicy> mergedMetadataPolicy = this.mergeMetadataPolicies(chain);
    if (log.isDebugEnabled()) {
      for (final String entityType : mergedMetadataPolicy.keySet()) {
        try {
          log.debug("Merged metadata policy for entity type: {}\n{}", entityType,
              OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(
                  this.metadataPolicySerializer.toJsonObject(mergedMetadataPolicy.get(entityType))));
        }
        catch (final JsonProcessingException e) {
          throw new RuntimeException(e);
        }
      }
    }

    // Check EntityConfiguration vs EntityStatement ending
    // Check Authority hints (Entity Configuration)
    final EntityMetadataInfoClaim targetEntityMetadata = this.getVerifiedLeafEntityStatement(chain);

    // Process metadata against policy
    final EntityMetadataInfoClaim policyProcessedMetadata =
        this.applyMetadataPolicy(targetEntityMetadata, mergedMetadataPolicy);

    // Collect results
    return ChainValidationResult.builder()
        .validatedChain(chain)
        .declaredMetadata(targetEntityMetadata)
        .policyProcessedMetadata(policyProcessedMetadata)
        .subjectTrustMarks(this.collectSubjectTrustMarks(chain))
        .build();
  }

  private List<EntityStatement> orderChain(final List<EntityStatement> unorderedChain) throws ChainValidationException {
    // Find the Entity Configurations
    final List<EntityStatement> entityConfigurations = unorderedChain.stream()
        .filter(entityStatement -> entityStatement.getSubject().equals(entityStatement.getIssuer()))
        .toList();

    // Find the Entity statements
    final List<EntityStatement> entityStatements = unorderedChain.stream()
        .filter(entityStatement -> !entityStatement.getSubject().equals(entityStatement.getIssuer()))
        .toList();

    // Get List of issuers
    final List<String> issuers = entityStatements.stream().map(EntityStatement::getIssuer).toList();
    // Get the TA = the Entity Configuration listed as Issuer of en Entity Statement
    final EntityStatement taEntityConfiguration = entityConfigurations.stream()
        .filter(entityStatement -> issuers.contains(entityStatement.getSubject()))
        .findFirst()
        .orElseThrow(
            () -> new ChainValidationException("No Trust anchor Entity Configuration found matching the path"));
    final EntityStatement targetEntityConfiguration = entityConfigurations.stream()
        .filter(entityStatement -> !entityStatement.getSubject().equals(taEntityConfiguration.getSubject()))
        .findFirst()
        .orElseThrow(() -> new ChainValidationException("No target Entity Configuration found"));

    // We have the TA and the target. Let's build the path of entity statements
    final List<EntityStatement> path = new ArrayList<>(List.of(taEntityConfiguration));
    String currentIssuer = taEntityConfiguration.getSubject();
    for (int i = 0; i < entityStatements.size(); i++) {
      final String finalCurrentIssuer = currentIssuer;
      final EntityStatement nextEntityStatement = entityStatements.stream()
          .filter((EntityStatement entityStatement) -> entityStatement.getIssuer().equals(finalCurrentIssuer))
          .findFirst()
          .orElseThrow(
              () -> new ChainValidationException("No next Entity Statement found for issuer: " + finalCurrentIssuer));
      path.add(nextEntityStatement);
      currentIssuer = nextEntityStatement.getSubject();
    }
    final EntityStatement lastEntityStatement = path.get(path.size() - 1);
    if (targetEntityConfiguration.getSubject().equals(lastEntityStatement.getSubject())) {
      path.add(targetEntityConfiguration);
      return path;
    }
    throw new ChainValidationException(
        "Target Entity Configuration does not match the last Entity Statement of the path");
  }

  private List<TrustMarkClaim> collectSubjectTrustMarks(final List<EntityStatement> chain) {

    final EntityStatement leafStatement = chain.get(chain.size() - 1);
    final EntityStatement superiorStatement = chain.get(chain.size() - 2);
    final String subject = leafStatement.getSubject();
    final List<TrustMarkClaim> trustMarks = new ArrayList<>(
        Optional.ofNullable(leafStatement.getTrustMarks()).orElse(new ArrayList<>()));

    if (superiorStatement.getSubject().equals(subject)) {
      // If the superior statement is issued for the subject,
      // then collect any trust marks not present in the leaf statement
      final List<TrustMarkClaim> superiorStatementTrustMarks = Optional.ofNullable(superiorStatement.getTrustMarks())
          .orElse(new ArrayList<>());
      superiorStatementTrustMarks.stream()
          .filter(supTrustMark -> trustMarks.stream()
              .noneMatch(subjTrustMark -> supTrustMark.getTrustMarkId().equals(subjTrustMark.getTrustMarkId())))
          .forEach(trustMarks::add);
    }
    return trustMarks;
  }

  private EntityMetadataInfoClaim applyMetadataPolicy(final EntityMetadataInfoClaim targetMetadata,
      final Map<String, EntityTypeMetadataPolicy> mergedMetadataPolicy) throws ChainValidationException {

    try {
      if (targetMetadata == null) {
        throw new ChainValidationException("Leaf entity has no metadata");
      }
      // Create a new updatable metadata object for processed metadata based on existing metadata
      final Map<String, Object> metadataJsonObject = new HashMap<>(OidcUtils.toJsonObject(targetMetadata));

      for (final String entityType : metadataJsonObject.keySet()) {
        // Process metadata for each key type
        // Note that metadata policies are unique per language tag as per OpenID federation standard.
        // No attempts are made to enforce e.g., organization_name policy on an organization_nam#sv metadata value
        if (mergedMetadataPolicy.containsKey(entityType)) {
          // This is always true if there is any metadata to process
          final Map<String, MetadataParameterPolicy> entityTypeMetadataPolicy = mergedMetadataPolicy.get(entityType)
              .getMetadataParameterPolicyMap();
          final Map<String, Object> targetEntityTypeMetadata = new HashMap<>(
              OidcUtils.toJsonObject(metadataJsonObject.get(entityType)));
          for (final String metadataParamName : targetEntityTypeMetadata.keySet()) {
            // Process each metadata parameter
            if (entityTypeMetadataPolicy.containsKey(metadataParamName)) {
              final Object processedMetadataValue = this.metadataPolicyProcessor.processPolicyParam(
                  targetEntityTypeMetadata.get(metadataParamName),
                  entityTypeMetadataPolicy.get(metadataParamName));
              // Store new value
              targetEntityTypeMetadata.put(metadataParamName, processedMetadataValue);
            }
          }
          // Put result entity type metadata values
          metadataJsonObject.put(entityType, targetEntityTypeMetadata);
        }
      }

      return OidcUtils.readJsonObject(metadataJsonObject, EntityMetadataInfoClaim.class);

    }
    catch (final PolicyTranslationException | PolicyProcessingException e) {
      throw new ChainValidationException("Failed to process metadata against policy", e);
    }

  }

  private EntityMetadataInfoClaim getVerifiedLeafEntityStatement(final List<EntityStatement> chain)
      throws ChainValidationException {

    final EntityStatement leafEntityStatement = chain.get(chain.size() - 1);
    if (this.isSelfSigned(leafEntityStatement)) {
      log.debug("Leaf statement is a self signed Entity Configuration statement");
      // This is an Entity Configuration. Check authority hints
      final EntityStatement superiorEntityStatement = chain.get(chain.size() - 2);
      final List<String> authorityHints = leafEntityStatement.getAuthorityHints();
      /*
        The below code was removed to ignore any checks for authority hints.
        The check that Entity Configuration hints to the Entity that issued its Entity Statement was removed
        as this is not a requirement.
        There is a requirement for EntityConfigurations to contain at least one authority hint. But this is only
        needed to allow path discovery (bottom up), but it is not necessary to validate the chain, thus ignored here.
      */
      /*
      if (authorityHints == null || authorityHints.isEmpty()) {
        throw new ChainValidationException("Leaf Entity Configuration has no authority hints");
      if (!authorityHints.contains(superiorEntityStatement.getIssuer())) {
        throw new ChainValidationException("Superior entity is not in authority hints of Entity Configuration");
      }
      */
      // Collect the metadata from leaf configuration, updated with superior statement metadata.
      return this.getCollectedMetadata(leafEntityStatement.getMetadata(),
          superiorEntityStatement.getMetadata());
    }
    else {
      log.debug("Leaf statement is an Entity Statement issued by a superior entity");
      // The leaf statement is an Entity Statement and not Entity Configuration.
      // Check that leaf entity statement subject_data_publication claim has declared "none" as the publication type
      final String subjectDataPublication = leafEntityStatement.getSubjectEntityConfigurationLocation();
      if (subjectDataPublication == null) {
        throw new ChainValidationException(
            "Chain ends with Entity Statement without declaring subject_entity_configuration_location");
      }
      else {
        throw new ChainValidationException(
            "Chain ends with Entity Statement despite having a subject_entity_configuration_location claim. Resolve this claim first and amend the chain");
      }
    }
  }

  private EntityMetadataInfoClaim getCollectedMetadata(EntityMetadataInfoClaim leafMetadata,
      EntityMetadataInfoClaim superiorMetadata)
      throws ChainValidationException {

    leafMetadata = Optional.ofNullable(leafMetadata).orElse(EntityMetadataInfoClaim.builder().build());
    superiorMetadata = Optional.ofNullable(superiorMetadata).orElse(EntityMetadataInfoClaim.builder().build());
    final Map<String, Object> collectedMetadataObject = new HashMap<>();

    final Map<String, Object> leafObjects = OidcUtils.toJsonObject(leafMetadata);
    final Map<String, Object> superiorObjects = OidcUtils.toJsonObject(superiorMetadata);

    final List<String> entityTypes = this.getAllKeys(leafObjects, superiorObjects);

    for (final String entityType : entityTypes) {
      if (!superiorObjects.containsKey(entityType)) {
        // No metadata set in superior statement. Use metadata from leaf statement.
        collectedMetadataObject.put(entityType, leafObjects.get(entityType));
        continue;
      }
      if (!leafObjects.containsKey(entityType)) {
        // No metadata set in leaf statement. Use metadata from superior statement.
        collectedMetadataObject.put(entityType, superiorObjects.get(entityType));
        continue;
      }
      // Metadata is present both in leaf and superior statements. Join them and give precedence to superior data.
      final Map<String, Object> superiorMetadataParams = OidcUtils.toJsonObject(superiorObjects.get(entityType));
      final Map<String, Object> leafMetadataParams = OidcUtils.toJsonObject(leafObjects.get(entityType));
      final Map<String, Object> collectedMetadataParams = new HashMap<>();
      final List<String> metadataParams = this.getAllKeys(superiorMetadataParams, leafMetadataParams);

      for (final String metadataParam : metadataParams) {
        final Object collectedParam = superiorMetadataParams.containsKey(metadataParam)
            ? superiorMetadataParams.get(metadataParam)
            : leafMetadataParams.get(metadataParam);
        collectedMetadataParams.put(metadataParam, collectedParam);
      }
      collectedMetadataObject.put(entityType, collectedMetadataParams);
    }
    return OidcUtils.readJsonObject(collectedMetadataObject, EntityMetadataInfoClaim.class);
  }

  private List<String> getAllKeys(Map<String, ?> firstMap, Map<String, ?> secondMap) {
    firstMap = Optional.ofNullable(firstMap).orElse(new HashMap<>());
    secondMap = Optional.ofNullable(secondMap).orElse(new HashMap<>());
    final List<String> keyList = new ArrayList<>(firstMap.keySet());
    secondMap.keySet().stream()
        .filter(entityType -> !keyList.contains(entityType))
        .forEach(keyList::add);
    return keyList;
  }

  private Map<String, EntityTypeMetadataPolicy> mergeMetadataPolicies(final List<EntityStatement> chain)
      throws ChainValidationException {

    try {
      // The list of unmerged relevant policies.
      final List<Map<String, EntityTypeMetadataPolicy>> chainMetadataPolicies = new ArrayList<>();

      final EntityStatement leafStatement = chain.get(chain.size() - 1);
      final EntityMetadataInfoClaim leafMetadata = Optional.ofNullable(leafStatement.getMetadata())
          .orElse(EntityMetadataInfoClaim.builder().build());
      final Map<String, Object> leafEntityMetadataJsonObject = OidcUtils.toJsonObject(leafMetadata);
      // Create a list of leaf entity types for which we will collect metadata policies
      final List<String> leafEntityTypes = leafEntityMetadataJsonObject.keySet().stream()
          .filter(
              s -> leafEntityMetadataJsonObject.get(s) != null && !((Map<?, ?>) leafEntityMetadataJsonObject.get(
                  s)).isEmpty())
          .toList();

      for (final EntityStatement entityStatement : chain) {
        final Map<String, Object> metadataPolicyObj = OidcUtils.toJsonObject(
            Optional.ofNullable(entityStatement.getMetadataPolicy()).orElse(EntityMetadataInfoClaim.builder().build()));
        final List<String> criticalPolicyOperators =
            Optional.ofNullable(entityStatement.getMetadataPolicyCriticalClaims())
                .orElse(List.of());
        // Create a metadata policy map keyed by entity type for collecting policies for this entity statement
        final Map<String, EntityTypeMetadataPolicy> metadataPolicyMap = new HashMap<>();
        for (final String entityType : leafEntityTypes) {
          if (metadataPolicyObj.containsKey(entityType) && !((Map<?, ?>) metadataPolicyObj.get(entityType)).isEmpty()) {
            // Read policy json object for this entity type
            final EntityTypeMetadataPolicy metadataPolicy = this.metadataPolicySerializer.fromJsonObject(
                OidcUtils.toJsonObject(metadataPolicyObj.get(entityType)),
                criticalPolicyOperators);
            metadataPolicyMap.put(entityType, metadataPolicy);
          }
        }
        if (!metadataPolicyMap.isEmpty()) {
          chainMetadataPolicies.add(metadataPolicyMap);
        }
      }

      // Merge policies
      final Map<String, EntityTypeMetadataPolicy> mergedMetadataPolicies = new HashMap<>();
      // Set initial empty policies
      leafEntityTypes
          .forEach(entityType -> mergedMetadataPolicies.put(entityType, EntityTypeMetadataPolicy.builder().build()));

      for (final Map<String, EntityTypeMetadataPolicy> entityPolicyMap : chainMetadataPolicies) {
        for (final String entityType : leafEntityTypes) {
          final EntityTypeMetadataPolicy mergedWithSubordinate = mergedMetadataPolicies.get(entityType)
              .mergeWithSubordinate(entityPolicyMap.get(entityType));
          mergedMetadataPolicies.put(entityType, mergedWithSubordinate);
        }
      }

      return mergedMetadataPolicies;
    }
    catch (final PolicyTranslationException | PolicyProcessingException | PolicyMergeException e) {
      throw new ChainValidationException("Error processing metadata policies in the chain", e);
    }
  }

  private void checkCriticalClaims(final List<EntityStatement> chain) throws ChainValidationException {
    if (chain.stream()
        .map(EntityStatement::getCriticalClaims)
        .filter(criticalClaims -> criticalClaims != null && !criticalClaims.isEmpty())
        .anyMatch(criticalClaims -> !new HashSet<>(this.supportedCriticalClaims).containsAll(criticalClaims))
    ) {
      throw new ChainValidationException("Unsupported critical claims declaration in Entity Statement");
    }
  }

  private void checkConstraints(final List<EntityStatement> chain) throws ChainValidationException {
    for (int i = 1; i < chain.size(); i++) {
      this.verifyIndividualConstraint(chain.get(i - 1).getConstraints(), chain.subList(i, chain.size()));
    }
  }

  private void verifyIndividualConstraint(final ConstraintsClaim constraints,
      final List<EntityStatement> subordinateStatements)
      throws ChainValidationException {
    if (constraints == null) {
      return;
    }
    if (subordinateStatements.isEmpty()) {
      return;
    }

    // Extract constraints components
    final Integer maxPathLength = constraints.getMaxPathLength();
    final List<String> allowedLeafEntityTypes = constraints.getAllowedLeafEntityTypes();
    final NamingConstraints namingConstraints = Optional.ofNullable(constraints.getNamingConstraints())
        .orElse(new NamingConstraints());
    final List<String> excluded = namingConstraints.getExcluded();
    final List<String> permitted = namingConstraints.getPermitted();
    final EntityStatement leafStatement = subordinateStatements.get(subordinateStatements.size() - 1);
    final EntityMetadataInfoClaim leafMetadata = Optional.ofNullable(leafStatement.getMetadata())
        .orElse(EntityMetadataInfoClaim.builder().build());
    final Map<String, Object> leafEntityMetadataJsonObject = OidcUtils.toJsonObject(leafMetadata);
    final List<String> leafEntityTypes = leafEntityMetadataJsonObject.keySet().stream()
        .filter(s -> !"federation_entity".equals(s))
        .filter(
            s -> leafEntityMetadataJsonObject.get(s) != null && !((Map<?, ?>) leafEntityMetadataJsonObject.get(
                s)).isEmpty())
        .toList();
    final List<String> subjectEntityIdentifiers = subordinateStatements.stream()
        .map(EntityStatement::getSubject)
        .toList();

    // Check max path length = the number of allowed intermediates
    if (maxPathLength != null) {
      int intermediateCount = subordinateStatements.size();
      if (this.isSelfSigned(leafStatement)) {
        // This implementation allows a chain to end with an Entity Statement.
        // If the last statement is selfsigned it is not counted as an Intermediate Entity statement
        intermediateCount -= 1;
      }
      if (intermediateCount > maxPathLength) {
        throw new ChainValidationException("Max path length constraints check failed");
      }
    }

    // Check naming constraints
    if (excluded != null && !excluded.isEmpty()) {
      // Fail if any subject Entity Identifier starts with any declared excluded name
      if (subjectEntityIdentifiers.stream().anyMatch(subjectId -> excluded.stream().anyMatch(subjectId::startsWith))
      ) {
        throw new ChainValidationException("Excluded name constraints violation");
      }
    }
    if (permitted != null && !permitted.isEmpty()) {
      // Fail if not all subject Entity Identifiers starts with at least one of the permitted names
      if (!subjectEntityIdentifiers.stream()
          .allMatch(subjectId -> permitted.stream().anyMatch(subjectId::startsWith))) {
        throw new ChainValidationException("Permitted name constraints violation");
      }
    }

    // Check leaf entity types
    if (allowedLeafEntityTypes != null && !allowedLeafEntityTypes.isEmpty()) {
      if (!new HashSet<>(allowedLeafEntityTypes).containsAll(leafEntityTypes)) {
        throw new ChainValidationException("Leaf entity type constraints violation");
      }
    }
  }

  private void checkSignatures(final List<EntityStatement> chain) throws ChainValidationException {

    try {
      // Verify that TA is trusted
      this.verifyEntityStatementSignature(chain.get(0), this.trustedKeys);
      // Verify that TA is selfsigned
      this.verifyEntityStatementSignature(chain.get(0), chain.get(0).getJwkSet());
      // Verify validity time
      this.verifyValidityTime(chain.get(0));

      // Verify that all other statements can
      for (int i = 1; i < chain.size(); i++) {
        this.verifyEntityStatementSignature(chain.get(i), chain.get(i - 1).getJwkSet());
        this.verifyValidityTime(chain.get(i));
      }
    }
    catch (final ParseException e) {
      throw new ChainValidationException("Signature validation error", e);
    }
  }

  private void verifyValidityTime(final EntityStatement entityStatement) throws ChainValidationException {

    if (entityStatement.getIssueTime() == null) {
      throw new ChainValidationException("Entity Statement has no issue time");
    }

    if (entityStatement.getExpirationTime() == null) {
      throw new ChainValidationException("Entity Statement has no expiration time");
    }

    final Instant issueTime = Instant.ofEpochMilli(entityStatement.getIssueTime().getTime());
    if (Instant.now().isBefore(issueTime.minusSeconds(15))) {
      throw new ChainValidationException("Entity Statement issue time is in the future");
    }

    final Instant expirationTime = Instant.ofEpochMilli(entityStatement.getExpirationTime().getTime());
    if (Instant.now().isAfter(expirationTime)) {
      throw new ChainValidationException("Entity Statement has expired");
    }
  }

  private boolean isSelfSigned(final EntityStatement entityStatement) {
    try {
      if (!entityStatement.getSubject().equals(entityStatement.getIssuer())) {
        return false;
      }
      this.verifyEntityStatementSignature(entityStatement, entityStatement.getJwkSet());
      return true;
    }
    catch (final ChainValidationException | ParseException e) {
      return false;
    }
  }

  private void verifyEntityStatementSignature(final EntityStatement entityStatement, final JWKSet jwkSet)
      throws ChainValidationException {
    try {
      if (!OidcUtils.verifySignedJWT(entityStatement.getSignedJWT(), jwkSet)) {
        throw new ChainValidationException("No matching trusted key found");
      }
    }
    catch (final JOSEException e) {
      throw new ChainValidationException("Signature validation error", e);
    }
  }
}
