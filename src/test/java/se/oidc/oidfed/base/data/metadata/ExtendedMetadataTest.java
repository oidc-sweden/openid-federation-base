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
package se.oidc.oidfed.base.data.metadata;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import se.oidc.oidfed.base.utils.OidcUtils;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests for extended metadata
 */
@Slf4j
class ExtendedMetadataTest {

  @Test
  void testExtendedMetadata() throws Exception {

    final ExtendedMetadata<OpMetadata> metadata = ExtendedMetadata.builder(OpMetadata.class)
        .baseMetadata(OpMetadata.builder()
            .issuer("issuer")
            .build())
        .addParameter("ext_param1", "value1")
        .addParameter("ext_param2", "value2")
        .build();

    final Map<String, Object> metadataJsonObject = metadata.toJsonObject();
    log.info("Extended metadata:\n{}",
        OidcUtils.OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(metadataJsonObject));

    final ExtendedMetadata<OpMetadata> parsedMetadata =
        new ExtendedMetadata<>(metadataJsonObject, OpMetadata.getJsonSerializer());

    final Map<String, Object> extendedParameters = parsedMetadata.getExtendedParameters();
    assertEquals(2, extendedParameters.size());
    assertEquals("value1", parsedMetadata.getExtendedParameter("ext_param1"));
    assertEquals("value2", parsedMetadata.getExtendedParameter("ext_param2"));
  }

}
