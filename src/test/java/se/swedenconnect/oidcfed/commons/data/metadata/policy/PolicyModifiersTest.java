package se.swedenconnect.oidcfed.commons.data.metadata.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSHeader;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.oidcfed.commons.configuration.MetadataParameter;
import se.swedenconnect.oidcfed.commons.configuration.PolicyParameterFormats;
import se.swedenconnect.oidcfed.commons.data.oidcfed.EntityMetadataInfoClaim;
import se.swedenconnect.oidcfed.commons.data.oidcfed.EntityStatement;
import se.swedenconnect.oidcfed.commons.data.oidcfed.EntityStatementDefinedParams;
import se.swedenconnect.oidcfed.commons.process.metadata.MetadataPolicySerializer;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyOperatorFactory;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyProcessingException;
import se.swedenconnect.oidcfed.commons.process.metadata.PolicyTranslationException;
import se.swedenconnect.oidcfed.commons.process.metadata.impl.DefaultPolicyOperatorFactory;
import se.swedenconnect.oidcfed.commons.process.metadata.impl.SkipSubordniatePolicyOperatorFactory;
import se.swedenconnect.oidcfed.commons.process.metadata.impl.StandardMetadataPolicySerializer;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.AddPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.DefaultPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.EssentialPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.IntersectsPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.OneOfPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.RegexpPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.SkipSubordinatesPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.SubsetOfPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.SupersetOfPolicyOperator;
import se.swedenconnect.oidcfed.commons.process.metadata.policyoperators.ValuePolicyOperator;
import se.swedenconnect.oidcfed.commons.testdata.PolicyData;
import se.swedenconnect.oidcfed.commons.testdata.TestCredentials;
import se.swedenconnect.oidcfed.commons.utils.OidcUtils;

/**
 * PolicyOperator tests
 */
@Slf4j
class PolicyModifiersTest {

  static PolicyOperatorFactory policyOperatorFactory;
  static MetadataPolicySerializer serializer;
  static PolicyOperatorFactory skipSubordinatesPolicyOperatorFactory;
  static MetadataPolicySerializer skipSubordinatesSerializer;

  @BeforeAll
  static void init() {
    policyOperatorFactory = DefaultPolicyOperatorFactory.getInstance();
    serializer = new StandardMetadataPolicySerializer(policyOperatorFactory,
      Arrays.stream(PolicyParameterFormats.values())
        .collect(
          Collectors.toMap(PolicyParameterFormats::getParameterName, PolicyParameterFormats::toMetadataParameter))
    );
    skipSubordinatesPolicyOperatorFactory = SkipSubordniatePolicyOperatorFactory.getInstance();
    skipSubordinatesSerializer = new StandardMetadataPolicySerializer(skipSubordinatesPolicyOperatorFactory,
      Arrays.stream(PolicyParameterFormats.values())
        .collect(
          Collectors.toMap(PolicyParameterFormats::getParameterName, PolicyParameterFormats::toMetadataParameter))
    );
  }

  @Test
  void policyModifiersTest() throws Exception {

    testPolicyOperators(
      "String value modifier with no value",
      PolicyParameterFormats.issuer.toMetadataParameter(),
      List.of(
        new PolicyData(ValuePolicyOperator.OPERATOR_NAME, null)
      ), PolicyProcessingException.class
    );
    testPolicyOperators(
      "String value modifier",
      PolicyParameterFormats.issuer.toMetadataParameter(),
      List.of(
        new PolicyData(ValuePolicyOperator.OPERATOR_NAME, "Value")
      ), null
    );
    testPolicyOperators(
      "String value with declared array values",
      PolicyParameterFormats.subject_types_supported.toMetadataParameter(),
      List.of(
        new PolicyData(DefaultPolicyOperator.OPERATOR_NAME, "Default Value")
      ), PolicyTranslationException.class
    );
    testPolicyOperators(
      "Declared array values",
      PolicyParameterFormats.subject_types_supported.toMetadataParameter(),
      List.of(
        new PolicyData(DefaultPolicyOperator.OPERATOR_NAME, List.of("Value1", "Value2"))
      ), null
    );
    testPolicyOperators(
      "Integer test",
      PolicyParameterFormats.default_max_age.toMetadataParameter(),
      List.of(
        new PolicyData(DefaultPolicyOperator.OPERATOR_NAME, 1234)
      ), null
    );
    testPolicyOperators(
      "Integer test with string input",
      PolicyParameterFormats.default_max_age.toMetadataParameter(),
      List.of(
        new PolicyData(DefaultPolicyOperator.OPERATOR_NAME, "1234")
      ), PolicyProcessingException.class
    );
    testPolicyOperators(
      "Illegal Integer test",
      PolicyParameterFormats.default_max_age.toMetadataParameter(),
      List.of(
        new PolicyData(DefaultPolicyOperator.OPERATOR_NAME, "M1234")
      ), PolicyTranslationException.class
    );
    testPolicyOperators(
      "Boolean test",
      PolicyParameterFormats.claims_parameter_supported.toMetadataParameter(),
      List.of(
        new PolicyData(DefaultPolicyOperator.OPERATOR_NAME, true)
      ), null
    );
    testPolicyOperators(
      "Boolean test string value",
      PolicyParameterFormats.claims_parameter_supported.toMetadataParameter(),
      List.of(
        new PolicyData(DefaultPolicyOperator.OPERATOR_NAME, "true")
      ), PolicyProcessingException.class
    );
    testPolicyOperators(
      "Illegal Boolean test",
      PolicyParameterFormats.claims_parameter_supported.toMetadataParameter(),
      List.of(
        new PolicyData(DefaultPolicyOperator.OPERATOR_NAME, "maybe")
      ), PolicyTranslationException.class
    );
    testPolicyOperators(
      "All values String test",
      PolicyParameterFormats.issuer.toMetadataParameter(),
      List.of(
        new PolicyData(ValuePolicyOperator.OPERATOR_NAME, "Value"),
        new PolicyData(AddPolicyOperator.OPERATOR_NAME, List.of("Value")),
        new PolicyData(DefaultPolicyOperator.OPERATOR_NAME, "Default"),
        new PolicyData(OneOfPolicyOperator.OPERATOR_NAME, List.of("Value", "Another value")),
        new PolicyData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("Value", "Another value")),
        new PolicyData(SupersetOfPolicyOperator.OPERATOR_NAME, List.of("Value")),
        new PolicyData(EssentialPolicyOperator.OPERATOR_NAME, true),
        new PolicyData(SkipSubordinatesPolicyOperator.OPERATOR_NAME, true),
        new PolicyData(RegexpPolicyOperator.OPERATOR_NAME, "^Value$"),
        new PolicyData(IntersectsPolicyOperator.OPERATOR_NAME, List.of("Value", "Another value"))
      ), null
    );
    testPolicyOperators(
      "All values String array test",
      PolicyParameterFormats.scopes_supported.toMetadataParameter(),
      List.of(
        new PolicyData(ValuePolicyOperator.OPERATOR_NAME, List.of("Value")),
        new PolicyData(AddPolicyOperator.OPERATOR_NAME, List.of("Another value")),
        new PolicyData(DefaultPolicyOperator.OPERATOR_NAME, List.of("Default")),
        new PolicyData(OneOfPolicyOperator.OPERATOR_NAME, List.of("Value", "Another value")),
        new PolicyData(SubsetOfPolicyOperator.OPERATOR_NAME, List.of("Value", "Another value")),
        new PolicyData(SupersetOfPolicyOperator.OPERATOR_NAME, List.of("Value")),
        new PolicyData(EssentialPolicyOperator.OPERATOR_NAME, true),
        new PolicyData(SkipSubordinatesPolicyOperator.OPERATOR_NAME, true),
        new PolicyData(RegexpPolicyOperator.OPERATOR_NAME, "^Value$"),
        new PolicyData(IntersectsPolicyOperator.OPERATOR_NAME, List.of("Value", "Another value"))
      ), null
    );

    testPolicyOperators(
      "Illegal mix - String array",
      PolicyParameterFormats.issuer.toMetadataParameter(),
      List.of(
        new PolicyData(ValuePolicyOperator.OPERATOR_NAME, List.of("Value", "Another value"))
      ), PolicyTranslationException.class
    );

    testPolicyOperators(
      "Space separated string",
      PolicyParameterFormats.issuer.toMetadataParameter(),
      List.of(
        new PolicyData(ValuePolicyOperator.OPERATOR_NAME, "scope1 scope2 scope3"),
        new PolicyData(AddPolicyOperator.OPERATOR_NAME, List.of("scope4")),
        new PolicyData(DefaultPolicyOperator.OPERATOR_NAME, "scope1 scope2"),
        new PolicyData(OneOfPolicyOperator.OPERATOR_NAME,
          List.of("scope1", "scope2", "scope3", "scope4")),
        new PolicyData(SubsetOfPolicyOperator.OPERATOR_NAME,
          List.of("scope1", "scope2", "scope3", "scope4")),
        new PolicyData(SupersetOfPolicyOperator.OPERATOR_NAME, List.of("scope1", "scope2"))
      ), null
    );
  }

  @Test
  void entityStatementParsingTest() throws Exception {

    EntityStatement entityStatement = EntityStatement.builder()
      .issuer("issuer")
      .subject("subject")
      .issueTime(new Date())
      .expriationTime(Date.from(Instant.now().plusSeconds(600)))
      .definedParams(EntityStatementDefinedParams.builder()
        .metadataPolicy(EntityMetadataInfoClaim.builder()
          .opMetadataObject(skipSubordinatesSerializer.toJsonObject(EntityTypeMetadataPolicy.builder()
            .addMetadataParameterPolicy(
              MetadataParameterPolicy.builder(PolicyParameterFormats.issuer.toMetadataParameter())
                .add(ValuePolicyOperator.OPERATOR_NAME, "Value")
                .add(RegexpPolicyOperator.OPERATOR_NAME, "test")
                .build())
            .addMetadataParameterPolicy(MetadataParameterPolicy.builder(
                PolicyParameterFormats.request_uri_parameter_supported.toMetadataParameter())
              .add(DefaultPolicyOperator.OPERATOR_NAME, true).build())
            .addMetadataParameterPolicy(
              MetadataParameterPolicy.builder(PolicyParameterFormats.scopes_supported.toMetadataParameter(), SkipSubordniatePolicyOperatorFactory.getInstance())
                .add(SupersetOfPolicyOperator.OPERATOR_NAME, List.of("openid"))
                .add(SkipSubordinatesPolicyOperator.OPERATOR_NAME, true)
                .build())
            .build()))
          .build())
        .build())
      .build(TestCredentials.p256JwtCredential, null);

    log.info("Entity Statement:\n{}", entityStatement.getSignedJWT().serialize());
    JWSHeader entityStatementHeader = entityStatement.getSignedJWT().getHeader();
    log.info("Header: \n{}", OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(
      entityStatementHeader.toJSONObject()));
    assertEquals("entity-statement+jwt", entityStatementHeader.getType().getType());

    Map<String, Object> entityStatementPayloadJsonObject = entityStatement.getSignedJWT()
      .getJWTClaimsSet()
      .toJSONObject();
    String entityStatementPayloadJson = OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
      .writeValueAsString(entityStatementPayloadJsonObject);
    log.info("Entity statement payload:\n{}", entityStatementPayloadJson);

    EntityMetadataInfoClaim metadataPolicyClaim = entityStatement.getMetadataPolicy();
    EntityTypeMetadataPolicy entityTypeMetadataPolicy = skipSubordinatesSerializer.fromJsonObject(
      metadataPolicyClaim.getOpMetadataObject(), new ArrayList<>());

    String entityPolicyJsonString = OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
      .writeValueAsString(skipSubordinatesSerializer.toJsonObject(entityTypeMetadataPolicy));
    log.info("OP Entity metadata policy:\n{}", entityPolicyJsonString);

    int sdf = 0;

  }

  private void testPolicyOperators(String description, MetadataParameter metadataParameter,
    List<PolicyData> policyDataList, Class<? extends Exception> exception)
    throws Exception {
    log.info(description);
    log.info("Metadata parameter: {}", metadataParameter);
    for (PolicyData policyData : policyDataList) {
      log.info("policy: {} with value: {}", policyData.getPolicy(), policyData.getValue());
    }
    log.info("Expected exception: {}", exception);

    if (exception == null) {
      MetadataParameterPolicy.MetadataParameterPolicyBuilder mdpBuilder = MetadataParameterPolicy.builder(
        metadataParameter, SkipSubordniatePolicyOperatorFactory.getInstance());
      for (PolicyData policyData : policyDataList) {
        mdpBuilder.add(policyData.getPolicy(), policyData.getValue());
      }
      MetadataParameterPolicy metadataParameterPolicy = mdpBuilder.build();
      EntityTypeMetadataPolicy entityTypeMetadataPolicy = EntityTypeMetadataPolicy.builder()
        .addMetadataParameterPolicy(metadataParameterPolicy)
        .build();

      String jsonString = OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter()
        .writeValueAsString(skipSubordinatesSerializer.toJsonObject(entityTypeMetadataPolicy));
      log.info("Policy modifiers JSON:\n{}", jsonString);
    }
    else {
      Exception caughtException = assertThrows(exception, () -> {
        MetadataParameterPolicy.MetadataParameterPolicyBuilder mdpBuilder = MetadataParameterPolicy.builder(
          metadataParameter);
        for (PolicyData policyData : policyDataList) {
          mdpBuilder.add(policyData.getPolicy(), policyData.getValue());
        }
        mdpBuilder.build();
      });
      log.info("Caught expected {} with message: {}", caughtException.getClass().getSimpleName(),
        caughtException.getMessage());
    }
    log.info("Test success\n");
  }

}