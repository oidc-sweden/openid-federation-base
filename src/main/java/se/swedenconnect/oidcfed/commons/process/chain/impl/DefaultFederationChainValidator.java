package se.swedenconnect.oidcfed.commons.process.chain.impl;

import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.lang.NonNull;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.oidcfed.commons.data.metadata.policy.EntityTypeMetadataPolicy;
import se.swedenconnect.oidcfed.commons.data.metadata.policy.MetadataParameterPolicy;
import se.swedenconnect.oidcfed.commons.data.oidcfed.ConstraintsClaim;
import se.swedenconnect.oidcfed.commons.data.oidcfed.EntityMetadataInfoClaim;
import se.swedenconnect.oidcfed.commons.data.oidcfed.EntityStatement;
import se.swedenconnect.oidcfed.commons.data.oidcfed.NamingConstraints;
import se.swedenconnect.oidcfed.commons.data.oidcfed.TrustMarkClaim;
import se.swedenconnect.oidcfed.commons.process.chain.ChainValidationException;
import se.swedenconnect.oidcfed.commons.process.chain.ChainValidationResult;
import se.swedenconnect.oidcfed.commons.process.chain.FederationChainValidator;
import se.swedenconnect.oidcfed.commons.process.metadata.MetadataPolicyProcessor;
import se.swedenconnect.oidcfed.commons.process.metadata.MetadataPolicySerializer;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyMergeException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyProcessingException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyTranslationException;
import se.swedenconnect.oidcfed.commons.utils.OidcUtils;

/**
 * Entity Statement chain validation implementation
 *
 * <p>
 * The definition of constraints is ambiguous. This implementation make two interpretations.
 * allowed_leaf_entity_types will ignore any presence of "federation_entity" as this type
 * can be used by any role. Naming constraints will be applied as URL prefix. Anything that matches
 * the beginning of this URL prefix, matches the constraint (permitted and excluded).
 * </p>
 * <p>
 * Also. No attempt to compare constraints is made. Instead. All constraints are individually processed against
 * their respective sub-path.
 * </p>
 */
@Slf4j
public class DefaultFederationChainValidator implements FederationChainValidator {

  private final JWKSet trustedKeys;
  private final MetadataPolicySerializer metadataPolicySerializer;
  private final MetadataPolicyProcessor metadataPolicyProcessor;

  @Setter private final List<String> supportedCriticalClaims = List.of(EntityStatement.SUBJECT_ENTITY_CONFIGURATION_LOCATION_CLAIM_NAME);

  /**
   * Constructor
   *
   * @param trustedKeys the keys trusted to verify Trust Anchor entity configuration statements
   * @param metadataPolicySerializer serializer for parsing metadata policy data
   */
  public DefaultFederationChainValidator(JWKSet trustedKeys, MetadataPolicySerializer metadataPolicySerializer) {
    this.trustedKeys = trustedKeys;
    this.metadataPolicySerializer = metadataPolicySerializer;
    this.metadataPolicyProcessor = new MetadataPolicyProcessor();
  }

  /** {@inheritDoc} */
  @Override public ChainValidationResult validate(@NonNull final List<EntityStatement> chain)
    throws ChainValidationException {

    // Check that chain has at least length = 2
    if (chain.size() < 2) {
      throw new ChainValidationException("Chain does not include at least two statements");
    }
    log.debug("Validating chain of length {}", chain.size());

    if (log.isTraceEnabled()) {
      log.trace("Chain to validate:");
      for (EntityStatement entityStatement : chain) {
        try {
          log.trace("Entity Statement issued by: {} - for: {}\n{}", entityStatement.getIssuer(),
            entityStatement.getSubject(),
            OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
              .writeValueAsString(entityStatement.getSignedJWT().getJWTClaimsSet().toJSONObject()));
        }
        catch (JsonProcessingException | ParseException e) {
          throw new RuntimeException(e);
        }
      }
    }

    // Check signatures
    checkSignatures(chain);
    log.debug("All signatures of the chain successfully validated");

    // Check constraints
    checkConstraints(chain);
    log.debug("Constraints successfully validated");

    // Check critical claims
    checkCriticalClaims(chain);
    log.debug("No unrecognized critical claims");

    // Metadata policy merge
    Map<String, EntityTypeMetadataPolicy> mergedMetadataPolicy = mergeMetadataPolicies(chain);
    if (log.isDebugEnabled()) {
      for (String entityType : mergedMetadataPolicy.keySet()) {
        try {
          log.debug("Merged metadata policy for entity type: {}\n{}", entityType,
            OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(
              metadataPolicySerializer.toJsonObject(mergedMetadataPolicy.get(entityType))));
        }
        catch (JsonProcessingException e) {
          throw new RuntimeException(e);
        }
      }
    }

    // Check EntityConfiguration vs EntityStatement ending
    // Check Authority hints (Entity Configuration)
    EntityMetadataInfoClaim targetEntityMetadata = getVerifiedLeafEntityStatement(chain);

    // Process metadata against policy
    EntityMetadataInfoClaim policyProcessedMetadata = applyMetadataPolicy(targetEntityMetadata, mergedMetadataPolicy);

    // Collect results
    return ChainValidationResult.builder()
      .validatedChain(chain)
      .declaredMetadata(targetEntityMetadata)
      .policyProcessedMetadata(policyProcessedMetadata)
      .subjectTrustMarks(collectSubjectTrustMarks(chain))
      .build();
  }

  private List<TrustMarkClaim> collectSubjectTrustMarks(List<EntityStatement> chain) {

    EntityStatement leafStatement = chain.get(chain.size() - 1);
    EntityStatement superiorStatement = chain.get(chain.size() - 2);
    String subject = leafStatement.getSubject();
    List<TrustMarkClaim> trustMarks = new ArrayList<>(
      Optional.ofNullable(leafStatement.getTrustMarks()).orElse(new ArrayList<>()));

    if (superiorStatement.getSubject().equals(subject)) {
      // If the superior statement is issued for the subject,
      // then collect any trust marks not present in the leaf statement
      List<TrustMarkClaim> superiorStatementTrustMarks = Optional.ofNullable(superiorStatement.getTrustMarks())
        .orElse(new ArrayList<>());
      superiorStatementTrustMarks.stream()
        .filter(supTrustMark -> trustMarks.stream()
          .noneMatch(subjTrustMark -> supTrustMark.getId().equals(subjTrustMark.getId())))
        .forEach(trustMarks::add);
    }
    return trustMarks;
  }

  private EntityMetadataInfoClaim applyMetadataPolicy(EntityMetadataInfoClaim targetMetadata,
    Map<String, EntityTypeMetadataPolicy> mergedMetadataPolicy) throws ChainValidationException {

    try {
      if (targetMetadata == null) {
        throw new ChainValidationException("Leaf entity has no metadata");
      }
      // Create a new updatable metadata object for processed metadata based on existing metadata
      Map<String, Object> metadataJsonObject = new HashMap<>(OidcUtils.toJsonObject(targetMetadata));

      for (String entityType : metadataJsonObject.keySet()) {
        // Process metadata for each key type
        // Note that metadata policies are unique per language tag as per OpenID federation standard.
        // No attempts are made to enforce e.g., organization_name policy on an organization_nam#sv metadata value
        if (mergedMetadataPolicy.containsKey(entityType)) {
          // This is always true if there is any metadata to process
          Map<String, MetadataParameterPolicy> entityTypeMetadataPolicy = mergedMetadataPolicy.get(entityType)
            .getMetadataParameterPolicyMap();
          Map<String, Object> targetEntityTypeMetadata = new HashMap<>(
            OidcUtils.toJsonObject(metadataJsonObject.get(entityType)));
          for (String metadataParamName : targetEntityTypeMetadata.keySet()) {
            // Process each metadata parameter
            if (entityTypeMetadataPolicy.containsKey(metadataParamName)) {
              Object processedMetadataValue = metadataPolicyProcessor.processPolicyParam(
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
    catch (PolicyTranslationException | PolicyProcessingException | JsonProcessingException e) {
      throw new ChainValidationException("Failed to process metadata against policy", e);
    }

  }

  private EntityMetadataInfoClaim getVerifiedLeafEntityStatement(List<EntityStatement> chain)
    throws ChainValidationException {

    EntityStatement leafEntityStatement = chain.get(chain.size() - 1);
    if (isSelfSigned(leafEntityStatement)) {
      log.debug("Leaf statement is a self signed Entity Configuration statement");
      // This is an Entity Configuration. Check authority hints
      EntityStatement superiorEntityStatement = chain.get(chain.size() - 2);
      List<String> authorityHints = leafEntityStatement.getAuthorityHints();
      if (authorityHints == null || authorityHints.isEmpty()) {
        throw new ChainValidationException("Leaf Entity Configuration has no authority hints");
      }
      if (!authorityHints.contains(superiorEntityStatement.getIssuer())) {
        throw new ChainValidationException("Superior entity is not in authority hints of Entity Configuration");
      }
      // Collect the metadata from leaf configuration, updated with superior statement metadata.
      return getCollectedMetadata(leafEntityStatement.getMetadata(),
        superiorEntityStatement.getMetadata());
    }
    else {
      log.debug("Leaf statement is an Entity Statement issued by a superior entity");
      // The leaf statement is an Entity Statement and not Entity Configuration.
      // Check that leaf entity statement subject_data_publication claim has declared "none" as the publication type
      String subjectDataPublication = leafEntityStatement.getSubjectEntityConfigurationLocation();
      if (subjectDataPublication == null) {
        throw new ChainValidationException(
          "Chain ends with Entity Statement without declaring subject_entity_configuration_location");
      } else {
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
    Map<String, Object> collectedMetadataObject = new HashMap<>();

    Map<String, Object> leafObjects = OidcUtils.toJsonObject(leafMetadata);
    Map<String, Object> superiorObjects = OidcUtils.toJsonObject(superiorMetadata);

    List<String> entityTypes = getAllKeys(leafObjects, superiorObjects);

    for (String entityType : entityTypes) {
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
      Map<String, Object> superiorMetadataParams = OidcUtils.toJsonObject(superiorObjects.get(entityType));
      Map<String, Object> leafMetadataParams = OidcUtils.toJsonObject(leafObjects.get(entityType));
      Map<String, Object> collectedMetadataParams = new HashMap<>();
      List<String> metadataParams = getAllKeys(superiorMetadataParams, leafMetadataParams);

      for (String metadataParam : metadataParams) {
        Object collectedParam = superiorMetadataParams.containsKey(metadataParam)
          ? superiorMetadataParams.get(metadataParam)
          : leafMetadataParams.get(metadataParam);
        collectedMetadataParams.put(metadataParam, collectedParam);
      }
      collectedMetadataObject.put(entityType, collectedMetadataParams);
    }

    try {
      return OidcUtils.readJsonObject(collectedMetadataObject, EntityMetadataInfoClaim.class);
    }
    catch (JsonProcessingException e) {
      throw new ChainValidationException("Illegal collected metadata", e);
    }

  }

  private List<String> getAllKeys(Map<String, ?> firstMap, Map<String, ?> secondMap) {
    firstMap = Optional.ofNullable(firstMap).orElse(new HashMap<>());
    secondMap = Optional.ofNullable(secondMap).orElse(new HashMap<>());
    List<String> keyList = new ArrayList<>(firstMap.keySet());
    secondMap.keySet().stream()
      .filter(entityType -> !keyList.contains(entityType))
      .forEach(keyList::add);
    return keyList;
  }

  private Map<String, EntityTypeMetadataPolicy> mergeMetadataPolicies(List<EntityStatement> chain)
    throws ChainValidationException {

    try {
      // The list of unmerged relevant policies.
      List<Map<String, EntityTypeMetadataPolicy>> chainMetadataPolicies = new ArrayList<>();

      EntityStatement leafStatement = chain.get(chain.size() - 1);
      EntityMetadataInfoClaim leafMetadata = Optional.ofNullable(leafStatement.getMetadata())
        .orElse(EntityMetadataInfoClaim.builder().build());
      Map<String, Object> leafEntityMetadataJsonObject = OidcUtils.toJsonObject(leafMetadata);
      // Create a list of leaf entity types for which we will collect metadata policies
      List<String> leafEntityTypes = leafEntityMetadataJsonObject.keySet().stream()
        .filter(
          s -> leafEntityMetadataJsonObject.get(s) != null && !((Map) leafEntityMetadataJsonObject.get(s)).isEmpty())
        .toList();

      for (EntityStatement entityStatement : chain) {
        Map<String, Object> metadataPolicyObj = OidcUtils.toJsonObject(
          Optional.ofNullable(entityStatement.getMetadataPolicy()).orElse(EntityMetadataInfoClaim.builder().build()));
        List<String> criticalPolicyOperators = Optional.ofNullable(entityStatement.getMetadataPolicyCriticalClaims())
          .orElse(List.of());
        // Create a metadata policy map keyed by entity type for collecting policies for this entity statement
        Map<String, EntityTypeMetadataPolicy> metadataPolicyMap = new HashMap<>();
        for (String entityType : leafEntityTypes) {
          if (metadataPolicyObj.containsKey(entityType) && !((Map) metadataPolicyObj.get(entityType)).isEmpty()) {
            // Read policy json object for this entity type
            EntityTypeMetadataPolicy metadataPolicy = metadataPolicySerializer.fromJsonObject(
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
      Map<String, EntityTypeMetadataPolicy> mergedMetadataPolicies = new HashMap<>();
      // Set initial empty policies
      leafEntityTypes
        .forEach(entityType -> mergedMetadataPolicies.put(entityType, EntityTypeMetadataPolicy.builder().build()));

      for (Map<String, EntityTypeMetadataPolicy> entityPolicyMap : chainMetadataPolicies) {
        for (String entityType : leafEntityTypes) {
          EntityTypeMetadataPolicy mergedWithSubordinate = mergedMetadataPolicies.get(entityType)
            .mergeWithSubordinate(entityPolicyMap.get(entityType));
          mergedMetadataPolicies.put(entityType, mergedWithSubordinate);
        }
      }

      return mergedMetadataPolicies;
    }
    catch (PolicyTranslationException | PolicyProcessingException | PolicyMergeException e) {
      throw new ChainValidationException("Error processing metadata policies in the chain", e);
    }
  }

  private void checkCriticalClaims(List<EntityStatement> chain) throws ChainValidationException {
    if (chain.stream()
      .map(EntityStatement::getCriticalClaims)
      .filter(criticalClaims -> criticalClaims != null && !criticalClaims.isEmpty())
      .anyMatch(criticalClaims -> !new HashSet<>(supportedCriticalClaims).containsAll(criticalClaims))
    ) {
      throw new ChainValidationException("Unsupported critical claims declaration in Entity Statement");
    }
  }

  private void checkConstraints(List<EntityStatement> chain) throws ChainValidationException {
    for (int i = 1; i < chain.size(); i++) {
      verifyIndividualConstraint(chain.get(i - 1).getConstraints(), chain.subList(i, chain.size()));
    }
  }

  private void verifyIndividualConstraint(ConstraintsClaim constraints, List<EntityStatement> subordinateStatements)
    throws ChainValidationException {
    if (constraints == null) {
      return;
    }
    if (subordinateStatements.isEmpty()) {
      return;
    }

    // Extract constraints components
    Integer maxPathLength = constraints.getMaxPathLength();
    List<String> allowedLeafEntityTypes = constraints.getAllowedLeafEntityTypes();
    NamingConstraints namingConstraints = Optional.ofNullable(constraints.getNamingConstraints())
      .orElse(new NamingConstraints());
    List<String> excluded = namingConstraints.getExcluded();
    List<String> permitted = namingConstraints.getPermitted();
    EntityStatement leafStatement = subordinateStatements.get(subordinateStatements.size() - 1);
    EntityMetadataInfoClaim leafMetadata = Optional.ofNullable(leafStatement.getMetadata())
      .orElse(EntityMetadataInfoClaim.builder().build());
    Map<String, Object> leafEntityMetadataJsonObject = OidcUtils.toJsonObject(leafMetadata);
    List<String> leafEntityTypes = leafEntityMetadataJsonObject.keySet().stream()
      .filter(s -> !"federation_entity".equals(s))
      .filter(
        s -> leafEntityMetadataJsonObject.get(s) != null && !((Map) leafEntityMetadataJsonObject.get(s)).isEmpty())
      .toList();
    List<String> subjectEntityIdentifiers = subordinateStatements.stream()
      .map(EntityStatement::getSubject)
      .toList();

    // Check max path length = the number of allowed intermediates
    if (maxPathLength != null) {
      int intermediateCount = subordinateStatements.size();
      if (isSelfSigned(leafStatement)) {
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

  private void checkSignatures(List<EntityStatement> chain) throws ChainValidationException {

    try {
      // Verify that TA is trusted
      verifyEntityStatementSignature(chain.get(0), trustedKeys);
      // Verify that TA is selfsigned
      verifyEntityStatementSignature(chain.get(0), chain.get(0).getJwkSet());
      // Verify validity time
      verifyValidityTime(chain.get(0));

      // Verify that all other statements can
      for (int i = 1; i < chain.size(); i++) {
        verifyEntityStatementSignature(chain.get(i), chain.get(i - 1).getJwkSet());
        verifyValidityTime(chain.get(i));
      }
    }
    catch (ParseException e) {
      throw new ChainValidationException("Signature validation error", e);
    }
  }

  private void verifyValidityTime(EntityStatement entityStatement) throws ChainValidationException {

    if (entityStatement.getIssueTime() == null) {
      throw new ChainValidationException("Entity Statement has no issue time");
    }

    if (entityStatement.getExpirationTime() == null) {
      throw new ChainValidationException("Entity Statement has no expiration time");
    }

    Instant issueTime = Instant.ofEpochMilli(entityStatement.getIssueTime().getTime());
    if (Instant.now().isBefore(issueTime.minusSeconds(15))) {
      throw new ChainValidationException("Entity Statement issue time is in the future");
    }

    Instant expirationTime = Instant.ofEpochMilli(entityStatement.getExpirationTime().getTime());
    if (Instant.now().isAfter(expirationTime)) {
      throw new ChainValidationException("Entity Statement has expired");
    }
  }

  private boolean isSelfSigned(EntityStatement entityStatement) {
    try {
      if (!entityStatement.getSubject().equals(entityStatement.getIssuer())) {
        return false;
      }
      verifyEntityStatementSignature(entityStatement, entityStatement.getJwkSet());
      return true;
    }
    catch (ChainValidationException | ParseException e) {
      return false;
    }
  }

  private void verifyEntityStatementSignature(EntityStatement entityStatement, JWKSet jwkSet)
    throws ChainValidationException {
    try {
      if (!OidcUtils.verifySignedJWT(entityStatement.getSignedJWT(), jwkSet)) {
        throw new ChainValidationException("No matching trusted key found");
      }
    }
    catch (JOSEException e) {
      throw new ChainValidationException("Signature validation error", e);
    }
  }
}
