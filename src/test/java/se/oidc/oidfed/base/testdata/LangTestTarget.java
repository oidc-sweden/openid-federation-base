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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.oidc.oidfed.base.data.LanguageObject;
import se.oidc.oidfed.base.data.LanguageTaggedJson;

import java.util.List;

/**
 * Target data file for language tagged data
 */
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
@NoArgsConstructor
@AllArgsConstructor
public class LangTestTarget implements LanguageTaggedJson {

  @JsonProperty("nolang")
  private String nolang;

  @JsonProperty("lang_def")
  private LanguageObject<String> langDefault;

  @JsonProperty("lang_nodef")
  private LanguageObject<String> langNoDefault;

  @JsonProperty("lang_onlydef")
  private LanguageObject<String> langOnlyDefault;

  @Override
  public List<String> getLanguageTaggedParameters() {
    return List.of("lang_def", "lang_nodef", "lang_onlydef");
  }
}
