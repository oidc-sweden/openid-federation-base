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

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import se.oidc.oidfed.base.data.LanguageObject;
import se.oidc.oidfed.base.data.LanguageTaggedJson;

import java.util.List;
import java.util.Map;

/**
 * Test JSON serialization of abstract data
 */
public class AbstractBaseClass implements LanguageTaggedJson {

  public AbstractBaseClass() {
    this.organizationName = LanguageObject.builder(String.class)
        .defaultValue("Default value")
        .langValue("sv", "Svenska")
        .langValue("en", "English")
        .build();
    this.signedJwksUri = "https://example.com/jwks";
  }

  @Override
  public List<String> getLanguageTaggedParameters() {
    return List.of("organization_name");
  }

  @JsonProperty("organization_name")
  @Getter
  protected LanguageObject<String> organizationName;

  @JsonProperty("signed_jwks_uri")
  @Getter
  protected String signedJwksUri;

  @JsonProperty("jwks")
  protected Map<String, Object> jwkSet;

}
