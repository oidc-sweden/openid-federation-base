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

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.minidev.json.annotate.JsonIgnore;
import org.springframework.util.CollectionUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Data class holding the values associated with zero or more language tags
 *
 * @param <T> Class of the language tagged objects
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class LanguageObject<T> {

  /** The value of a present value without language tag (There can only be one) */
  @JsonProperty("def")
  private T defaultValue;
  /** Language tagged values with the language identifier as key */
  @JsonProperty("lang_values")
  private Map<String, T> valueMap;

  @JsonIgnore
  public T getLanguageValue(final String preferredLanguage) {
    if (this.defaultValue == null && CollectionUtils.isEmpty(this.valueMap)) {
      return null;
    }
    final T firstAvailable = this.defaultValue == null
        ? this.valueMap.values().stream().findFirst().get()
        : this.defaultValue;

    return !CollectionUtils.isEmpty(this.valueMap) && this.valueMap.containsKey(preferredLanguage)
        ? this.valueMap.get(preferredLanguage)
        : firstAvailable;
  }

  public static <V> LanguageObjectBuilder<V> builder(final Class<V> valueClass) {
    return new LanguageObjectBuilder<>();
  }

  public static class LanguageObjectBuilder<T> {

    LanguageObject<T> languageObject;

    private LanguageObjectBuilder() {
      this.languageObject = new LanguageObject<>();
    }

    public LanguageObjectBuilder<T> defaultValue(final T defaultValue) {
      this.languageObject.defaultValue = defaultValue;
      return this;
    }

    public LanguageObjectBuilder<T> valueMap(final Map<String, T> valueMap) {
      this.languageObject.valueMap = valueMap;
      return this;
    }

    public LanguageObjectBuilder<T> langValue(final String language, final T value) {
      final Map<String, T> valueMap = Optional.ofNullable(this.languageObject.getValueMap())
          .orElse(new HashMap<>());
      valueMap.put(language, value);
      this.languageObject.valueMap = valueMap;
      return this;
    }

    public LanguageObject<T> build() {
      return this.languageObject;
    }

  }

}
