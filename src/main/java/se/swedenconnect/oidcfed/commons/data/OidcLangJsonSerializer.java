package se.swedenconnect.oidcfed.commons.data;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.util.StringUtils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import se.swedenconnect.oidcfed.commons.utils.OidcUtils;

/**
 * Instances of this class converts OIDC language tagged json to data classes where all language tagged
 * data is consolidated to a {@link LanguageObject} object. This object holds all language versions
 * of this parameter along with any default value that was declared without language tag.
 * <p>
 * The JSON object converter converts all parameters that has a language tag in order to ensure
 * that any extensible parameters on present in the target class also gets converted to a single
 * JSON parameter. It also ensures that a list of parameter names that has been declared as
 * language parameters in the target class gets converted in order to allow the result JSON
 * object data to be converted into a target class object of type T.
 * <p>
 * Direct access to the function consolidateLanguageTags(final Map<String, Object> languageTaggedMap,
 * List<String> declaredLangParameters) allows JSON object data conversion with custom set of declared
 * parameters with can be useful to use if no defined target class is used. A generic JsonOidcLangConverter
 * for this use can be instantiated with:
 *
 * <code>
 * JsonOidcLangConverter<GenericLangTarget> converter = new JsonOidcLangConverter<>(GenericLangTarget.class)
 * </code>
 */
public class OidcLangJsonSerializer<T extends LanguageTaggedJson> {

  private final List<String> targetDeclaredLangParameters;
  private final ObjectMapper objectMapper;

  private final Class<T> targetClass;

  private boolean prettyPrinting = false;

  /**
   * Constructor
   *
   * @param targetClass the target class for deserialization of language tagged JSON data
   */
  public OidcLangJsonSerializer(final Class<T> targetClass) {
    this(targetClass, OidcUtils.getOidcObjectMapper());
  }

  /**
   * Constructor with custom {@link ObjectMapper}
   *
   * @param targetClass the target class for deserialization of language tagged JSON data
   * @param objectMapper the object mapper used for serialization and deserialization of JSON
   */
  public OidcLangJsonSerializer(final Class<T> targetClass, final ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
    this.targetClass = targetClass;
    try {
      this.targetDeclaredLangParameters = targetClass.getDeclaredConstructor()
        .newInstance()
        .getLanguageTaggedParameters();
    }
    catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
      throw new IllegalArgumentException("Illegal target class declaration");
    }
  }

  /**
   * Sets pretty printing option.
   *
   * @param prettyPrinting boolean setting pretty printing option
   * @return this serializer to support cascading
   */
  public OidcLangJsonSerializer<T> setPrettyPrinting(boolean prettyPrinting) {
    this.prettyPrinting = prettyPrinting;
    return this;
  }

  /**
   * Parse JSON string that may include language tagged data to the target object class
   *
   * @param languageTaggedJson JSON string which may contain language tagged data
   * @return target object storing language tagged data in {@link LanguageObject}
   * @throws JsonProcessingException error to parse JSON data
   */
  public T parse(String languageTaggedJson) throws JsonProcessingException {
    Map<String, Object> languageTaggedJsonObject = objectMapper.readValue(languageTaggedJson, new TypeReference<>() {
    });
    return parse(languageTaggedJsonObject);
  }

  /**
   * Parse JSON object that may contain language tagged data
   *
   * @param languageTaggedJsonObject JSON object
   * @return target object storing language tagged data in {@link LanguageObject}
   * @throws JsonProcessingException JsonProcessingException error to parse JSON data
   */
  public T parse(Map<String, Object> languageTaggedJsonObject) throws JsonProcessingException {
    Map<String, Object> stringObjectMap = consolidateLanguageTags(languageTaggedJsonObject);
    return objectMapper.readValue(
      objectMapper.writeValueAsString(stringObjectMap), targetClass);
  }

  /**
   * This method will replace all language tagged objects in the input map with an object of type {@link LanguageObject}.
   * keys in the input map will be treated as language tags either if a key contains the "#" value or if
   * the key matches any of the parameter names in the defaultKnownLangParameters list.
   *
   * @param languageTaggedMap input map to be consolidated
   * @return consolidated Map.
   */
  public Map<String, Object> consolidateLanguageTags(final Map<String, Object> languageTaggedMap) {
    return consolidateLanguageTags(languageTaggedMap, this.targetDeclaredLangParameters);
  }

  /**
   * This method will replace all language tagged objects in the input map with an object of type {@link LanguageObject}.
   * keys in the input map will be treated as language tags either if a key contains the "#" value or if
   * the key matches any of the parameter names in the defaultKnownLangParameters list.
   *
   * @param declaredLangParameters a list of parameter names that has been declared in the target class to be a language tagged object.
   * @param languageTaggedMap input map to be consolidated
   * @return consolidated Map.
   */
  public Map<String, Object> consolidateLanguageTags(final Map<String, Object> languageTaggedMap,
    List<String> declaredLangParameters) {

    Map<String, Object> consolidatetMap = new HashMap<>(languageTaggedMap);
    List<String> langKeys = getLanguageTaggedKeys(languageTaggedMap);

    // Process all map keys that has been identified to have a language tag
    for (String langKey : langKeys) {
      // Find all versions of this lang tagged map key
      List<String> correlatedKeys = languageTaggedMap.keySet().stream()
        .filter(key -> key.startsWith(langKey))
        .filter(key -> !key.equals(langKey))
        .collect(Collectors.toList());
      // Build LanguageObjectMap
      Map<String, Object> languageObjectMap = new HashMap<>();
      for (String correlatedKey : correlatedKeys) {
        String lang = correlatedKey.substring(correlatedKey.indexOf("#") + 1);
        if (StringUtils.hasText(lang)) {
          languageObjectMap.put(lang, languageTaggedMap.get(correlatedKey));
        }
        // Remove correlated key from consolidated map
        consolidatetMap.remove(correlatedKey);
      }
      // Get any untagged default value (or null if no such key exists)
      Object defaultValue = languageTaggedMap.get(langKey);

      // Add consolidated Lang object
      consolidatetMap.put(langKey, new LanguageObject<>(defaultValue, languageObjectMap));
      // Delete correlated tagged keys
    }

    // Process all known tag names that are identified as language tagged parameters
    for (String declaredParameter : declaredLangParameters) {
      // Only process those tags that was not processed above.
      if (langKeys.contains(declaredParameter)) {
        // This has already been processed. Skip to next
        continue;
      }
      if (languageTaggedMap.containsKey(declaredParameter)) {
        // This parameter has a default value with no correlated language tagged keys. Store it as default value only
        consolidatetMap.put(declaredParameter, new LanguageObject<>(languageTaggedMap.get(declaredParameter), null));
      }
    }
    return consolidatetMap;
  }

  private List<String> getLanguageTaggedKeys(Map<String, Object> languageTaggedMap) {

    List<String> langKeyList = new ArrayList<>();

    languageTaggedMap.keySet().stream()
      .filter(key -> key.contains("#"))
      .forEach(key -> {
        String propName = key.substring(0, key.indexOf("#"));
        if (StringUtils.hasText(propName)) {
          if (!langKeyList.contains(propName)) {
            langKeyList.add(propName);
          }
        }
      });
    return langKeyList;
  }

  public String toJson(T serlizingObject) throws JsonProcessingException {
    // Start with serializing the object to JSON object map
    String primaryJson = objectMapper.writeValueAsString(serlizingObject);
    Map<String, Object> primaryJsonObject = objectMapper.readValue(primaryJson, new TypeReference<>() {
    });
    Map<String, Object> serializedJsonObject = new HashMap<>(primaryJsonObject);

    // Get lang tagged parameters
    List<String> languageTaggedParameters = serlizingObject.getLanguageTaggedParameters();

    for (String parameterName : languageTaggedParameters) {
      if (primaryJson.contains(parameterName)) {
        Object langObject = primaryJsonObject.get(parameterName);
        if (!(langObject instanceof Map)) {
          throw new RuntimeException("Object listed as language tagged is not a Map");
        }
        LanguageObject<?> parsedLangObject = objectMapper.readValue(
          objectMapper.writeValueAsString(langObject),
          LanguageObject.class
        );
        // Now convert the parsed Language data object to individual parameters in the primary JSON object
        serializedJsonObject.remove(parameterName);
        if (parsedLangObject.getDefaultValue() != null) {
          // Add default value without language tag
          serializedJsonObject.put(parameterName, parsedLangObject.getDefaultValue());
        }
        Map<?, ?> valueMap = Optional.ofNullable(parsedLangObject.getValueMap()).orElse(new HashMap<>());
        Set<?> languageList = valueMap.keySet();
        for (Object language : languageList) {
          // Add language tagged parameters
          serializedJsonObject.put(parameterName + "#" + language, valueMap.get(language));
        }
      }
    }
    // Now serialize the language tagged serialization object map
    if (prettyPrinting) {
      return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(serializedJsonObject);
    }
    return objectMapper.writeValueAsString(serializedJsonObject);
  }

  public Map<String, Object> toJsonObject(T serializingObject) throws JsonProcessingException {
    return objectMapper.readValue(toJson(serializingObject), new TypeReference<>() {
      }
    );
  }

}
