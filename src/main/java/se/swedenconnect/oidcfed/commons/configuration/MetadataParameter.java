package se.swedenconnect.oidcfed.commons.configuration;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Properties for a metadata parameter
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MetadataParameter {
  String name;
  String valueType;
}
