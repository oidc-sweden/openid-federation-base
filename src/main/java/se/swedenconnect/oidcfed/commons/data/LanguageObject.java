package se.swedenconnect.oidcfed.commons.data;

import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.type.TypeReference;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data class holding the values associated with zero or more language tags
 *
 * @param <T> Class of the language tagged objects
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class LanguageObject<T extends Object> {

  /** The value of a present value without language tag (There can only be one) */
  @JsonProperty("def")
  private T defaultValue;
  /** Language tagged values with the language identifier as key */
  @JsonProperty("lang_values")
  private Map<String, T> valueMap;

  public static <V> LanguageObjectBuilder<V> builder(Class<V> valueClass) {
    return new LanguageObjectBuilder<>();
  }

  public static class LanguageObjectBuilder<T extends Object> {

    LanguageObject<T> languageObject;

    private LanguageObjectBuilder() {
      this.languageObject = new LanguageObject<>();;
    }

    public LanguageObjectBuilder<T> defaultValue(T defaultValue) {
      this.languageObject.defaultValue = defaultValue;
      return this;
    }
    public LanguageObjectBuilder<T> valueMap(Map<String, T> valueMap) {
      this.languageObject.valueMap = valueMap;
      return this;
    }

    public LanguageObjectBuilder<T> langValue(String language, T value) {
      Map<String, T> valueMap = Optional.ofNullable(this.languageObject.getValueMap())
        .orElse(new HashMap<>());
      valueMap.put(language, value);
      this.languageObject.valueMap = valueMap;
      return this;
    }

    public LanguageObject<T> build() {
      return languageObject;
    }

  }

}
