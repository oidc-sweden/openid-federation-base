package se.swedenconnect.oidcfed.commons.data.metadata;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;

import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.oidcfed.commons.utils.OidcUtils;

/**
 * Tests for extended metadata
 */
@Slf4j
class ExtendedMetadataTest {


  @Test
  void testExtendedMetadata() throws Exception {

    ExtendedMetadata<OpMetadata> metadata = ExtendedMetadata.builder(OpMetadata.class)
      .baseMetadata(OpMetadata.builder()
        .issuer("issuer")
        .build())
      .addParameter("ext_param1", "value1")
      .addParameter("ext_param2", "value2")
      .build();

    Map<String, Object> metadataJsonObject = metadata.toJsonObject();
    log.info("Extended metadata:\n{}", OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(metadataJsonObject));

    ExtendedMetadata<OpMetadata> parsedMetadata = new ExtendedMetadata<>(metadataJsonObject, OpMetadata.getJsonSerializer());

    Map<String, Object> extendedParameters = parsedMetadata.getExtendedParameters();
    assertEquals(2, extendedParameters.size());
    assertEquals("value1", parsedMetadata.getExtendedParameter("ext_param1"));
    assertEquals("value2", parsedMetadata.getExtendedParameter("ext_param2"));
  }

}