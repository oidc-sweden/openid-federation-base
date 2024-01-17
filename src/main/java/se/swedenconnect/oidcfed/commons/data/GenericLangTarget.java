package se.swedenconnect.oidcfed.commons.data;

import java.util.List;

import lombok.NoArgsConstructor;

/**
 * A generic target class for language tagged data. This can be used to instantiate a {@link OidcLangJsonSerializer}
 * for generic conversion of arbitrary JSON objects with language tagged parameters.
 */
@NoArgsConstructor
public class GenericLangTarget implements LanguageTaggedJson{

  /** {@inheritDoc} */
  @Override public List<String> getLanguageTaggedParameters() {
    return List.of();
  }
}
