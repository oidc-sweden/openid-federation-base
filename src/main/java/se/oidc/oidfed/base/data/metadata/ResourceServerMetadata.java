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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.Getter;
import se.oidc.oidfed.base.data.OidcLangJsonSerializer;

import java.util.List;
import java.util.Map;

/**
 * Resource server metadata
 */
public class ResourceServerMetadata extends AbstractOidcFedMetadata {

  @JsonIgnore
  @Getter
  private static final OidcLangJsonSerializer<ResourceServerMetadata> jsonSerializer =
      new OidcLangJsonSerializer<>(ResourceServerMetadata.class);

  /**
   * Constructor
   */
  public ResourceServerMetadata() {
    this.addLanguageParametersTags(List.of());
  }

  /** {@inheritDoc} */
  @Override
  public String toJson(final boolean prettyPrinting) throws JsonProcessingException {
    return jsonSerializer.setPrettyPrinting(prettyPrinting).toJson(this);
  }

  /** {@inheritDoc} */
  @Override
  public Map<String, Object> toJsonObject() throws JsonProcessingException {
    return jsonSerializer.toJsonObject(this);
  }

  /**
   * Create builder for Resource Server metadata
   *
   * @return the builder
   */
  public static ResourceServerMetadataBuilder builder() {
    return new ResourceServerMetadataBuilder();
  }

  /**
   * Builder class for resource server metadata
   */
  public static class ResourceServerMetadataBuilder
      extends AbstractOidcFedMetadataBuilder<ResourceServerMetadata, ResourceServerMetadataBuilder> {

    /**
     * Private constructor
     */
    private ResourceServerMetadataBuilder() {
      super(new ResourceServerMetadata());
    }

    /** {@inheritDoc} */
    @Override
    ResourceServerMetadataBuilder getReturnedBuilderInstance() {
      return this;
    }

    /** {@inheritDoc} */
    @Override
    public ResourceServerMetadata build() {
      return this.metadata;
    }
  }
}
