package se.swedenconnect.oidcfed.commons.data;

import java.util.List;

/**
 * Interface for all Json POJO classes holding language tagged parameters
 */
public interface LanguageTaggedJson {

  /**
   * Get a list of parameter names that serializes to a {@link LanguageObject} object.
   *
   * @return list of language tagged parameters
   */
  List<String> getLanguageTaggedParameters();

}
