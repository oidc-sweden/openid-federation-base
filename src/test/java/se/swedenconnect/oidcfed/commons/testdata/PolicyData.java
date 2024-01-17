package se.swedenconnect.oidcfed.commons.testdata;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * Holder of a metadata policy operator data components for tests
 */
@AllArgsConstructor
@Data
public class PolicyData {

  String policy;
  Object value;

}
