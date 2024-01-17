package se.swedenconnect.oidcfed.commons.data.oidcfed;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Constraints data
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ConstraintsClaim {

  @JsonProperty("max_path_length")
  private Integer maxPathLength;

  @JsonProperty("naming_constraints")
  private NamingConstraints namingConstraints;

  @JsonProperty("allowed_leaf_entity_types")
  private List<String> allowedLeafEntityTypes;

}
