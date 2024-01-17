# SC OpenID federation

This library is a base library to support development of the OpenID federation standard.

This library faithfully implements the latest version of the OpenID federation specification draft,
but adds extensible features that are considered for a national Swedish OpenID federation profile.

## Extended features

This library addresses the challenges documented in [OIDC Sweden - OpenID Federation Challenges](https://github.com/oidc-sweden/specifications/blob/main/swedish-oidc-fed-challenges.md).

This means that the chain validation has implemented support for two extended features:

 - Support for validation of chains that ends with an Entity Statement (Chain does not have to terminate with an Entity Configuration)
 - Support metadata policy operator `skip_subordinates`, allowing to skip subordinate metadata policies from policy merge in chain validation.

Both features depend on the use of extensible data that is marked critical when used to prevent conflicting chain validation results

- Validation of a chain that ends with an Entity Statement requires this Entity Statement to contain the critical claim `subject_data_publication`
- The `skip_subordinates` policy operator MUST be marked critical when used.

All extended features are specified in [OIDC Sweden - OpenID Federation Profile](https://github.com/oidc-sweden/specifications/blob/main/swedish-oidc-fed-profile.md)

### Rationale for extended features

These extensions above are motivated by some essential identified needs:

**Simplified client registration**

Participation in OpenID federation places some quite tough requirements on all participating services. 
This is the fact in particular related to the creation and publication of signed data objects such as:

- Creation signing and publication of Entity Configuration at a .well-known location
- Signing requests to obtain Trust Marks

As these operations must involve the federation key of the service, 
such operations must be integrated with their federation software. 
This can become quite a challenge for less capable federation services such as public clients,
or even regular OIDC relying party services using standard OIDC software without advanced federation features.

The extended chain validation allows federation services to participate without having to publish their own Entity Configuration data.
The price of this is that they will only be discoverable and verifiable through compliant resolvers of the federation that
implements the extended chain validation.
But in a federation that implements a wide use of Resolvers, this can be a viable tradeoff.

**Allowing interconnection of federations with non-harmonized policies**

OpenID federation illustrates in its introduction how services can participate in multiple federations by chaining to multiple trust anchors.

This may be hard in practice unless all policies of the infrastructure are harmonized in a way that guarantees that
all policies can be successfully merged without merge conflicts.

The support of the `skip_subordinates` policy operator allows chain construction in all types of federation infrastructures,
by providing a mechanism for bypassing incompatible subordinate policies.

## Language support and extended serializers

This library implements extended serializers to support:

- Multi language support for metadata parameters
- Possible updates to metadata policy expression

**Language support**

Multi-language support is provided in all Metadata classes by assigning the metadata parameter to the LanguageObject value class.
When serialized to JSON, this object type produces language tagged json parameter names.
When JSON string is deserialized to a Java object, then a LanguageObject value is created, allowing structured access to language tagged data.

This functionality is implemented by the `se.swedenconnect.oidcfed.commons.data.OidcLangJsonSerializer`

**Metadata policy serialization**

The `se.swedenconnect.oidcfed.commons.process.metadata.MetadataPolicySerializer` provides an interface for serialization
of metadata policy between JSON and Java objects.
This allows independent customization of metadata policy expression formats, under discussion.
If the expression format changes, then this can be handled by a separate implementation of this serializer.


## Builder support

All essential federation data objects are supported by builders.

This is illustrated by the following example used to build and sign an Entity Statement object

    EntityStatement entityStatement = EntityStatement.builder()
      .issuer("issuer")
      .subject("subject")
      .expriationTime(Date.from(Instant.now().plusSeconds(180)))
      .issueTime(new Date())
      .definedParams(EntityStatementDefinedParams.builder()
        .authorityHints(List.of("hint1", "hint2"))
        .constraints(ConstraintsClaim.builder()
          .allowedLeafEntityTypes(List.of("openid_relying_party", "openid_provider"))
          .maxPathLength(2)
          .namingConstraints(NamingConstraints.builder()
            .excluded(List.of("https://example.com/excluded"))
            .permitted(List.of("https://example.com/permitted"))
            .build())
          .build())
        .subjectDataPublication(SubjectDataPublication.builder()
          .entityConfigurationPublicationType(SubjectDataPublication.PUBLICATION_TYPE_NONE)
          .build(), true)
        .addCriticalClaim("other_critical_claim")
        .jwkSet(getJwkSet(TestCredentials.p256Credential.getCertificate()))
        .metadata(EntityMetadataInfoClaim.builder()
          .opMetadataObject(OpMetadata.builder()
            .issuer("Issuer")
            .organizationName(LanguageObject.builder(String.class)
              .defaultValue("DIGG")
              .langValue("sv", "Svenska")
              .langValue("en", "English")
              .langValue("es", "Español")
              .build())
            .jwkSet(getJwkSet(TestCredentials.p521Credential.getCertificate()))
            .signedJwksUri("http://example.com/jwkset")
            .oidcSeDiscoUserMessageSupported(true)
            .oidcSeDiscoAuthnProviderSupported(true)
            .oidcSeDiscoUserMessageSupportedMimeTypes(List.of("text/plain"))
            .build().toJsonObject())
          .oidcRelyingPartyMetadataObject(RelyingPartyMetadata.builder()
            .organizationName(LanguageObject.builder(String.class)
              .defaultValue("DIGG")
              .langValue("sv", "Myndigheten för digital förvaltning")
              .langValue("en", "Government Agency for Digital Government")
              .build())
            .build().toJsonObject())
          .build())
        .addPolicyLanguageCriticalClaim(RegexpPolicyOperator.OPERATOR_NAME)
        .addPolicyLanguageCriticalClaim(ValuePolicyOperator.OPERATOR_NAME)
        .addPolicyLanguageCriticalClaim(SkipSubordinatesPolicyOperator.OPERATOR_NAME)
        .metadataPolicy(EntityMetadataInfoClaim.builder()
          .opMetadataObject(serializer.toJsonObject(EntityTypeMetadataPolicy.builder()
            .addMetadataParameterPolicy(MetadataParameterPolicy.builder(PolicyParameterFormats.issuer.toMetadataParameter())
              .add(RegexpPolicyOperator.OPERATOR_NAME, OidcUtils.URI_REGEXP)
              .build())
            .addMetadataParameterPolicy(MetadataParameterPolicy.builder(PolicyParameterFormats.acr_values_supported.toMetadataParameter())
              .add(SubsetOfPolicyOperator.OPERATOR_NAME,
                List.of("http://id.elegnamnden.se/loa/1.0/loa3", "http://id.elegnamnden.se/loa/1.0/loa4",
                "http://id.elegnamnden.se/loa/1.0/eidas-sub", "http://id.elegnamnden.se/loa/1.0/eidas-nf-sub",
                "http://id.elegnamnden.se/loa/1.0/eidas-high", "http://id.elegnamnden.se/loa/1.0/eidas-nf-high"))
              .add(RegexpPolicyOperator.OPERATOR_NAME, List.of(OidcUtils.URI_REGEXP, "^.{3,}$"))
              .build())
            .build()))
          .build())
        .sourceEndpoint("http://example.com/source")
        .trustMarkIssuers(TrustMarkIssuersBuilder.getInstance()
          .trustMark("https://example.com/tm1", List.of("https://example.com/issuer1"))
          .trustMark("https://example.com/tm2", List.of("https://example.com/issuer1", "https://example.com/issuer2"))
          .build())
        .trustMarks(List.of(
          TrustMarkClaim.builder()
            .id("https://example.com/tm1")
            .trustMark(TrustMark.builder()
              .id("https://example.com/tm1")
              .subject("https://example.com/subject")
              .issueTime(new Date())
              .issuer("https://example.com/trust_mark_issuer")
              .build(TestCredentials.p256JwtCredential, null).getSignedJWT().serialize())
            .build(),
          TrustMarkClaim.builder()
            .id("https://example.com/tm2")
            .trustMark("Signed trust mark JWT")
            .build()))
        .trustMarkOwners(TrustMarkOwnersBuilder.getInstance()
          .trustMark("https://example.com/tm1", "https://example.com/owner1", getJwkSet(TestCredentials.p256Credential.getCertificate()))
          .trustMark("https://example.com/tm2", "https://example.com/owner2", getJwkSet(TestCredentials.p256Credential.getCertificate()))
          .build())
        .build())
      .build(TestCredentials.p256JwtCredential, null);

The example and its necessary dependencies are illustrated in the EntityStatementTest class.

Parsing from Signed JWT back to java objects is illustrated by the following example:

    EntityStatement parsedEntityStatement = new EntityStatement(signedEntityStatementJwt);
    Map<String, Object> opMetadataObject = parsedEntityStatement.getMetadata().getOpMetadataObject();
    OpMetadata parsedOpMetadata = OpMetadata.getJsonSerializer().parse(opMetadataObject);



## Chain validation

This implementation separates chain validation from Trust Mark validation. 
The primary reason for this is that chain validation is used as a subcomponent of Trust Mark validation.

**Chain validation implementation**

Chain validation is supported by implementing the `se.swedenconnect.oidcfed.commons.process.chain.FederationChainValidator` interface.

A default implementation is provided by `se.swedenconnect.oidcfed.commons.process.chain.impl.DefaultFederationChainValidator`

This validator implements fully the standard and all extended features outlined above.


**Trust Mark validation implementation**

Trust Mark validation is supported by implementing the `se.swedenconnect.oidcfed.commons.process.chain.TrustMarkValidator` interface.

A default implementation is provided by `se.swedenconnect.oidcfed.commons.process.chain.impl.DefaultTrustMarkValidator`

The default implementation of the Trust Mark validator also requires implementations of:

 - `TrustMarkStatusResolver` - Providing the status of TrustMarks.
 - `FederationPathBuilder` - Providing the chain path from Trust Anchor to target entity.

These interfaces are not implemented in this library. They should be implemented by the service that makes use of this library.



