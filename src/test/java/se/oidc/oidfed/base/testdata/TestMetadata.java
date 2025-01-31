package se.oidc.oidfed.base.testdata;

import com.fasterxml.jackson.core.type.TypeReference;
import se.oidc.oidfed.base.utils.OidcUtils;

import java.io.IOException;
import java.util.Map;

public class TestMetadata {

  public static Map<String, Object> opMetadata;
  public static Map<String, Object> opMetadata_claims12;
  public static Map<String, Object> opMetadata_claims123;
  public static Map<String, Object> rpMetadata;
  public static Map<String, Object> rpMetadata_rt;
  public static Map<String, Object> federationEntityMetadata;

  static {
    try {
      opMetadata = OidcUtils.OBJECT_MAPPER.readValue(TestMetadata.class.getResource("/metadata/op-metadata.json"), new TypeReference<>() {});
      rpMetadata = OidcUtils.OBJECT_MAPPER.readValue(TestMetadata.class.getResource("/metadata/rp-metadata.json"), new TypeReference<>() {});
      federationEntityMetadata = OidcUtils.OBJECT_MAPPER.readValue(TestMetadata.class.getResource("/metadata/fe-metadata.json"), new TypeReference<>() {});
      rpMetadata_rt = OidcUtils.OBJECT_MAPPER.readValue(TestMetadata.class.getResource("/metadata/rp-metadata-resp-type.json"), new TypeReference<>() {});
      opMetadata_claims12 = OidcUtils.OBJECT_MAPPER.readValue(TestMetadata.class.getResource("/metadata/op-metadata-claims12.json"), new TypeReference<>() {});
      opMetadata_claims123 = OidcUtils.OBJECT_MAPPER.readValue(TestMetadata.class.getResource("/metadata/op-metadata-claims123.json"), new TypeReference<>() {});
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }
}
