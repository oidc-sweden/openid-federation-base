/*
 * Copyright 2024 OIDC Sweden
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.oidc.oidfed.base.utils;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import se.oidc.oidfed.base.configuration.ValueType;
import se.oidc.oidfed.base.process.metadata.PolicyTranslationException;

import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * OIDC Utils.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class OidcUtils {

  public static final ObjectMapper OBJECT_MAPPER = getOidcObjectMapper();
  public static final List<String> standardJwtClaims = List.of(
      "iss", "sub", "iat", "exp", "jti", "aud", "nbf"
  );
  public static final String URI_REGEXP = "^(http:\\/\\/|https:\\/\\/|urn:)[\\w\\W]*$";

  public static ObjectMapper getOidcObjectMapper() {
    final ObjectMapper objectMapper = new ObjectMapper();
    objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    objectMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, true);
    objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    return objectMapper;
  }

  /**
   * Extract all claims that are not listed as standard JWT claims and are not present in the exclude data object
   *
   * @param dataObject Data object containing parameters that are not part of the extension set
   * @param payload payload of the JWT from which the extension claims are collected
   * @return json object map containing the extension claims
   * @throws JsonProcessingException JSON processing errors
   */
  public static Map<String, Object> getExtensionProperties(final Map<String, Object> payload, Object dataObject)
      throws JsonProcessingException {
    Objects.requireNonNull(payload, "Null payload is not allowed");
    dataObject = Optional.ofNullable(dataObject).orElse(new HashMap<>());

    final Map<String, Object> extensionObjectMap = new HashMap<>();
    final List<String> payloadClaims = new ArrayList<>(payload.keySet());
    final Map<String, Object> dataObjectMap = OBJECT_MAPPER.readValue(OBJECT_MAPPER.writeValueAsString(dataObject),
        new TypeReference<>() {
        });
    for (final String claimName : payloadClaims) {
      if (standardJwtClaims.contains(claimName)) {
        continue;
      }
      if (dataObjectMap.containsKey(claimName)) {
        continue;
      }
      // This parameter in the payload is not a standard JWT claim and not part of the defined data object members. Add to extensions
      extensionObjectMap.put(claimName, payload.get(claimName));
    }
    return extensionObjectMap;
  }

  /**
   * Convert an object that must contain a List to a list of String values. The input object can be any of:
   *
   * <ul>
   *   <li>String</li>
   *   <li>Integer</li>
   *   <li>Boolean</li>
   *   <li>List of strings</li>
   *   <li>List of integers</li>
   *   <li>Space separated values in a string</li>
   * </ul>
   *
   * The output is a list of strings for all input types with any value converted to its string representation.
   *
   * @param valueList object holding a list of value objects
   * @param valueType type of object expected
   * @return list of values as {@link List<String>}
   * @throws PolicyTranslationException error processing the input with the declared type
   */
  public static List<String> convertListToStringList(final Object valueList, final String valueType) throws
      PolicyTranslationException {
    try {
      return convertListToStringList((List<Object>) valueList, valueType);
    }
    catch (final Exception ex) {
      throw new PolicyTranslationException("Input object is not a List");
    }
  }

  /**
   * Convert a List object to a list of String values. The input object can be any of:
   *
   * <ul>
   *   <li>String</li>
   *   <li>Integer</li>
   *   <li>Boolean</li>
   *   <li>List of strings</li>
   *   <li>List of integers</li>
   *   <li>Space separated values in a string</li>
   * </ul>
   *
   * The output is a list of strings for all input types with any value converted to its string representation.
   *
   * @param valueList list of value objects
   * @param valueType type of object expected
   * @return list of values as {@link List<String>}
   * @throws PolicyTranslationException error processing the input with the declared type
   */
  public static List<String> convertListToStringList(final List<Object> valueList, final String valueType) throws
      PolicyTranslationException {
    if (valueList == null) {
      return null;
    }
    final List<String> stringValueList = new ArrayList<>();
    for (final Object valueObject : valueList) {
      stringValueList.add(verifyValueType(valueObject, valueType));
    }
    return stringValueList;
  }

  /**
   * Convert an object to a list of String values. The input object can be any of:
   *
   * <ul>
   *   <li>String</li>
   *   <li>Integer</li>
   *   <li>Boolean</li>
   *   <li>List of strings</li>
   *   <li>List of integers</li>
   *   <li>Space separated values in a string</li>
   * </ul>
   *
   * The output is a list of strings for all input types with any value converted to its string representation.
   *
   * @param value value object
   * @param valueType type of object expected
   * @return list of values as {@link List<String>}
   * @throws PolicyTranslationException error processing the input with the declared type
   */
  public static List<String> convertToStringList(final Object value, final String valueType)
      throws PolicyTranslationException {
    if (value == null) {
      return null;
    }
    try {
      switch (valueType) {
      case ValueType.STRING:
      case ValueType.INTEGER:
      case ValueType.BOOLEAN:
        return List.of(verifyValueType(value, valueType));
      case ValueType.STRING_ARRAY:
      case ValueType.BOOLEAN_ARRAY:
      case ValueType.INTEGER_ARRAY:
        if (!(value instanceof List<?>)) {
          throw new PolicyTranslationException("Value is not an array: " + value);
        }
        final List<String> valueList = new ArrayList<>();
        for (final Object valueItem : (List<?>) value) {
          valueList.add(verifyValueType(valueItem, valueType));
        }
        return valueList;
      case ValueType.SPACE_SEPARATED_STRINGS:
        if (value instanceof List<?>) {
          // The policy value will be expressed as a list of strings, but the policy modifier provided a list. Use it.
          final List<String> ssValueList = new ArrayList<>();
          for (final Object valueItem : (List<?>) value) {
            ssValueList.add(verifyValueType(valueItem, valueType));
          }
          return ssValueList;
        }
        // A single string value was given. Divide space separated strings to List
        return Arrays.stream(verifyValueType(value, valueType).split(" ")).toList();
      default:
        throw new PolicyTranslationException("Illegal value type");
      }
    }
    catch (final ClassCastException e) {
      throw new PolicyTranslationException("Value translation failed", e);
    }
  }

  public static String verifyValueType(final Object value, final String valueType) throws PolicyTranslationException {
    switch (valueType) {
    case ValueType.STRING:
    case ValueType.STRING_ARRAY:
    case ValueType.SPACE_SEPARATED_STRINGS:
      if (!(value instanceof String)) {
        throw new PolicyTranslationException("Illegal String value class: " + value.getClass());
      }
      return (String) value;
    case ValueType.INTEGER:
    case ValueType.INTEGER_ARRAY:
      if (value instanceof Integer) {
        return String.valueOf(value);
      }
      if (value instanceof String) {
        try {
          return String.valueOf(Integer.parseInt((String) value));
        }
        catch (final NumberFormatException numberFormatException) {
          throw new PolicyTranslationException("Illegal integer value: " + value);
        }
      }
      throw new PolicyTranslationException("Illegal Boolean value: " + value);
    case ValueType.BOOLEAN:
    case ValueType.BOOLEAN_ARRAY:
      if (value instanceof Boolean) {
        return String.valueOf(value);
      }
      if (value instanceof String) {
        final String booleanString = ((String) value).toLowerCase();
        if (booleanString.equals("true") | booleanString.equals("false")) {
          return booleanString;
        }
      }
      throw new PolicyTranslationException("Illegal Boolean value: " + value);
    default:
      throw new PolicyTranslationException("Unsupported value type: " + valueType);
    }
  }

  public static Object convertToValueObject(final List<String> value, final String valueType)
      throws PolicyTranslationException {

    if (value == null || value.isEmpty()) {
      return null;
    }

    if (valueType.equals(ValueType.STRING)
        || valueType.equals(ValueType.INTEGER)
        || valueType.equals(ValueType.BOOLEAN)) {
      if (value.size() > 1) {
        throw new PolicyTranslationException("Multi valued list provided for single value ValueTYpe");
      }
    }

    switch (valueType) {
    case ValueType.STRING:
      return value.get(0);
    case ValueType.INTEGER:
      try {
        return Integer.parseInt(value.get(0));
      }
      catch (final NumberFormatException e) {
        throw new PolicyTranslationException("Invalid integer value");
      }
    case ValueType.BOOLEAN:
      if (value.get(0).equalsIgnoreCase("true") || value.get(0).equalsIgnoreCase("false")) {
        return Boolean.parseBoolean(value.get(0));
      }
      else {
        throw new PolicyTranslationException("Invalid boolean value");
      }
    case ValueType.STRING_ARRAY:
      return value;
    case ValueType.SPACE_SEPARATED_STRINGS:
      return String.join(" ", value);
    case ValueType.INTEGER_ARRAY:
      final List<Integer> integerList = new ArrayList<>();
      for (final String intValue : value) {
        try {
          integerList.add(Integer.parseInt(intValue));
        }
        catch (final NumberFormatException e) {
          throw new PolicyTranslationException("Invalid integer value");
        }
      }
      return integerList;
    default:
      throw new PolicyTranslationException("Invalid value type: " + valueType);
    }
  }

  public static JWSVerifier getVerifier(final JWK jwk) throws JOSEException {

    final KeyType keyType = jwk.getKeyType();
    if (keyType.equals(KeyType.EC)) {
      return new ECDSAVerifier(jwk.toECKey());
    }
    if (keyType.equals(KeyType.RSA)) {
      return new RSASSAVerifier(jwk.toRSAKey());
    }
    throw new JOSEException("Unsupported key type");
  }

  public static boolean verifySignedJWT(final SignedJWT signedJWT, final JWKSet jwkSet) throws JOSEException {

    for (final JWK jwk : jwkSet.getKeys()) {
      if (signedJWT.verify(getVerifier(jwk))) {
        return true;
      }
    }
    return false;
  }

  public static void verifyValidityTime(final SignedJWT signedJWT) throws ParseException, JOSEException {
    verifyValidityTime(signedJWT, 15);
  }

  public static void verifyValidityTime(final SignedJWT signedJWT, final int timeSkew)
      throws ParseException, JOSEException {

    final JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

    if (claimsSet.getIssueTime() == null) {
      throw new JOSEException("Entity Statement has no issue time");
    }

    if (claimsSet.getExpirationTime() == null) {
      throw new JOSEException("Entity Statement has no expiration time");
    }

    final Instant issueTime = Instant.ofEpochMilli(claimsSet.getIssueTime().getTime());
    if (Instant.now().isBefore(issueTime.minusSeconds(timeSkew))) {
      throw new JOSEException("Entity Statement issue time is in the future");
    }

    final Instant expirationTime = Instant.ofEpochMilli(claimsSet.getExpirationTime().getTime());
    if (Instant.now().isAfter(expirationTime)) {
      throw new JOSEException("Entity Statement has expired");
    }
  }

  public static Map<String, Object> toJsonObject(final Object object) {
    try {
      return OBJECT_MAPPER.readValue(OBJECT_MAPPER.writeValueAsString(object), new TypeReference<>() {
      });
    }
    catch (final JsonProcessingException e) {
      throw new RuntimeException(e);
    }

  }

  public static <T> T readJsonObject(final Map<String, Object> jsonObject, final Class<T> targetClassType)
      throws JsonProcessingException {
    return OBJECT_MAPPER.readValue(OBJECT_MAPPER.writeValueAsString(jsonObject), targetClassType);
  }

}
