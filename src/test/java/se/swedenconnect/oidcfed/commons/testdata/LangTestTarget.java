package se.swedenconnect.oidcfed.commons.testdata;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import se.swedenconnect.oidcfed.commons.data.LanguageObject;
import se.swedenconnect.oidcfed.commons.data.LanguageTaggedJson;

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
  private LanguageObject<String>  langNoDefault;

  @JsonProperty("lang_onlydef")
  private LanguageObject<String>  langOnlyDefault;

  @Override public List<String> getLanguageTaggedParameters() {
    return List.of("lang_def", "lang_nodef", "lang_onlydef");
  }
}
