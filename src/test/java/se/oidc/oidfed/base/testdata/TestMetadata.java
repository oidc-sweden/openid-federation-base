package se.oidc.oidfed.base.testdata;

import se.oidc.oidfed.base.utils.OidcUtils;
import tools.jackson.core.type.TypeReference;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.Map;

public class TestMetadata {

  public static Map<String, Object> opMetadata;
  public static Map<String, Object> opMetadata_claims12;
  public static Map<String, Object> opMetadata_claims123;
  public static Map<String, Object> rpMetadata;
  public static Map<String, Object> rpMetadata_rt;
  public static Map<String, Object> federationEntityMetadata;

  static {
    opMetadata = load("/metadata/op-metadata.json");
    rpMetadata = load("/metadata/rp-metadata.json");
    federationEntityMetadata = load("/metadata/fe-metadata.json");
    rpMetadata_rt = load("/metadata/rp-metadata-resp-type.json");
    opMetadata_claims12 = load("/metadata/op-metadata-claims12.json");
    opMetadata_claims123 = load("/metadata/op-metadata-claims123.json");
  }

  /**
   * Reads a JSON class path resource into a JSON object map.
   * <p>
   * The resource is opened as a stream rather than passed as a {@link java.net.URL}, since Jackson 3 removed the
   * {@code readValue(URL, ...)} overloads.
   *
   * @param resource path of the class path resource
   * @return the parsed JSON object map
   */
  private static Map<String, Object> load(final String resource) {
    try (final InputStream is = TestMetadata.class.getResourceAsStream(resource)) {
      if (is == null) {
        throw new IllegalStateException("Test metadata resource not found: " + resource);
      }
      return OidcUtils.JSON_MAPPER.readValue(is, new TypeReference<>() {
      });
    }
    catch (final IOException e) {
      throw new UncheckedIOException("Failed to read test metadata resource: " + resource, e);
    }
  }
}
