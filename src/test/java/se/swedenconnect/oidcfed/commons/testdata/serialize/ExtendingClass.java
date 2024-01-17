package se.swedenconnect.oidcfed.commons.testdata.serialize;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Builder;
import lombok.Getter;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ExtendingClass extends AbstractBaseClass {

  public ExtendingClass() {
    this.oidcSeDiscoUserMessageSupported = true;
  }

  @JsonIgnore
  @Override public List<String> getLanguageTaggedParameters() {
    List<String> allTags = new ArrayList<>(super.getLanguageTaggedParameters());
    allTags.addAll(List.of());
    return allTags;
  }

  /**
   * A discovery parameter specifying whether the OpenID Provider supports the https://id.oidc.se/param/userMessage
   * authentication request parameter
   */
  @JsonProperty("https://id.oidc.se/disco/userMessageSupported")
  @Getter private Boolean oidcSeDiscoUserMessageSupported;


}
