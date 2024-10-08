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
package se.oidc.oidfed.base.testdata.serialize;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;

import java.util.ArrayList;
import java.util.List;

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
  @Override
  public List<String> getLanguageTaggedParameters() {
    final List<String> allTags = new ArrayList<>(super.getLanguageTaggedParameters());
    allTags.addAll(List.of());
    return allTags;
  }

  /**
   * A discovery parameter specifying whether the OpenID Provider supports the https://id.oidc.se/param/userMessage
   * authentication request parameter
   */
  @JsonProperty("https://id.oidc.se/disco/userMessageSupported")
  @Getter
  private Boolean oidcSeDiscoUserMessageSupported;

}
