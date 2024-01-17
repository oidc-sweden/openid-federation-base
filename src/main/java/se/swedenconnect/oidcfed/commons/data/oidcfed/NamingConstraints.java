package se.swedenconnect.oidcfed.commons.data.oidcfed;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Naming constraits data
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class NamingConstraints {

  @JsonProperty("permitted")
  private List<String> permitted;

  @JsonProperty("excluded")
  private List<String> excluded;

}
