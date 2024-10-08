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
package se.oidc.oidfed.base.data;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.oidc.oidfed.base.testdata.LangTestTarget;
import se.oidc.oidfed.base.utils.OidcUtils;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for Json language converter
 */
@Slf4j
class OidcLangJsonSerializerTest {

  static String langTestJson1;
  static final ObjectMapper OBJECT_MAPPER = OidcUtils.getOidcObjectMapper();

  @BeforeAll
  static void init() throws Exception {
    langTestJson1 = FileUtils.readFileToString(
        new File(OidcLangJsonSerializerTest.class.getResource("/testdata/langTestJson1.json").getFile()),
        StandardCharsets.UTF_8);
  }

  @Test
  void consolidateTest() throws Exception {

    log.info("Testing language tag consolidation");
    log.info("Using test json:\n{}", langTestJson1);
    final OidcLangJsonSerializer<LangTestTarget> preparedConverter = new OidcLangJsonSerializer<>(LangTestTarget.class);
    final LangTestTarget defConsolidatedTarget = preparedConverter.parse(langTestJson1);
    assertEquals("Default value", defConsolidatedTarget.getLangDefault().getDefaultValue());
    assertEquals("Svenska", defConsolidatedTarget.getLangNoDefault().getValueMap().get("sv"));
    log.info("Default consolidation of JSON to Data object test success");

    log.info("Testing conversion using generic converter");
    final OidcLangJsonSerializer<GenericLangTarget> genericConverter =
        new OidcLangJsonSerializer<>(GenericLangTarget.class);
    final String genericConvertedJson = this.genericConvertToJsonObject(genericConverter, List.of());
    log.info("Generic converted JSON without explicit lang parameter list\n{}", genericConvertedJson);
    final MismatchedInputException mismatchedInputException = assertThrows(MismatchedInputException.class, () -> OBJECT_MAPPER.readValue(genericConvertedJson, LangTestTarget.class));
    log.info("Expected exception from deserialization of illegal JSON: {}", mismatchedInputException.getMessage());

    final String adaptedConvertedJson = this.genericConvertToJsonObject(genericConverter, List.of("lang_onlydef"));
    log.info("Generic converted JSON with explicit lang parameter list\n{}", adaptedConvertedJson);
    final LangTestTarget adaptedTarget = OBJECT_MAPPER.readValue(adaptedConvertedJson, LangTestTarget.class);
    assertEquals("Default value", adaptedTarget.getLangOnlyDefault().getDefaultValue());
    log.info("Deserialization success");
  }

  private String genericConvertToJsonObject(final OidcLangJsonSerializer<GenericLangTarget> genericConverter,
      final List<String> langParams) throws Exception {
    final Map<String, Object> convertPresent = genericConverter.consolidateLanguageTags(
        OBJECT_MAPPER.readValue(langTestJson1, new TypeReference<>() {
        }), langParams);
    return OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(convertPresent);
  }

}
