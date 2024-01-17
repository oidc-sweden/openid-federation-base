package se.swedenconnect.oidcfed.commons.data.oidcfed;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Subject Publication Data claim for Entity Statements
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SubjectDataPublication {

  public static final String CLAIM_NAME = "subject_data_publication";
  public static final String PUBLICATION_TYPE_NONE = "none";
  public static final String PUBLICATION_TYPE_WELL_KNOWN = "well_known";
  public static final String PUBLICATION_TYPE_CUSTOM = "custom";

  @JsonProperty("entity_configuration_publication_type")
  private String entityConfigurationPublicationType;

  @JsonProperty("entity_configuration_location")
  private String entityConfigurationLocation;

}
