// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;

namespace Cratis.AuthProxy.Aspire;

public static partial class AuthProxyExtensions
{
    /// <summary>
    /// Pairs AuthProxy's v1 HMAC-SHA256 forwarded-identity signer with an Arc backend's verifier.
    /// </summary>
    /// <typeparam name="T">The AuthProxy resource type.</typeparam>
    /// <typeparam name="TBackend">The backend resource type.</typeparam>
    /// <param name="builder">The AuthProxy resource builder.</param>
    /// <param name="backend">The backend that verifies forwarded identity.</param>
    /// <param name="audience">The audience, defaulting to the backend resource name.</param>
    /// <param name="keyId">The key identifier, defaulting to the AuthProxy resource name.</param>
    /// <param name="signingKey">A secret parameter containing a base64-encoded 32-byte key. Required when publishing.</param>
    /// <returns>The same resource builder for chaining.</returns>
    /// <exception cref="InvalidForwardedIdentityAudience">The audience is not 1-128 nonblank printable ASCII characters.</exception>
    /// <exception cref="InvalidForwardedIdentityKeyId">The key identifier is invalid or taken on this backend.</exception>
    /// <exception cref="ForwardedIdentityAlreadyPaired">This AuthProxy has already paired this backend.</exception>
    /// <exception cref="ConflictingForwardedIdentityAudience">Another pairing uses a different audience on this backend.</exception>
    /// <exception cref="ForwardedIdentitySigningKeyNotProvisioned">No signing key was supplied outside run mode.</exception>
    /// <exception cref="ArgumentException">The supplied signing key parameter is not marked secret.</exception>
    /// <remarks>
    /// Run mode generates a fresh in-memory key per backend, without a persisted default. Publish mode
    /// requires a provisioned secret parameter and emits only its reference. This method never logs the key.
    /// Pairing covers registered backend services and resource-based selectable-tenant endpoints, regardless
    /// of registration order. It configures Arc's verifier, not a local-development trust profile.
    /// </remarks>
    public static IResourceBuilder<T> WithSignedForwardingTo<T, TBackend>(
        this IResourceBuilder<T> builder,
        IResourceBuilder<TBackend> backend,
        string? audience = null,
        string? keyId = null,
        IResourceBuilder<ParameterResource>? signingKey = null)
        where T : IResourceWithEnvironment
        where TBackend : IResourceWithEnvironment
    {
        audience ??= backend.Resource.Name;
        keyId ??= builder.Resource.Name;
        ValidateForwardedIdentityNames(audience, keyId);
        ValidateForwardedIdentitySigningKey(signingKey?.Resource);

        var annotation = builder.Resource.Annotations.OfType<AuthProxyConfigAnnotation>().SingleOrDefault();
        if (annotation?.ForwardedIdentityPairings.ContainsKey(backend.Resource) == true)
        {
            throw new ForwardedIdentityAlreadyPaired(builder.Resource.Name, backend.Resource.Name);
        }

        var verifier = GetForwardedIdentityVerifier(backend.Resource, audience, keyId);
        signingKey ??= CreateForwardedIdentityKey(builder, backend.Resource);
        var pairing = new ForwardedIdentityPairing(audience, keyId, signingKey.Resource);
        annotation ??= GetOrCreateAnnotation(builder.Resource);
        annotation.ForwardedIdentityPairings.Add(backend.Resource, pairing);
        if (!backend.Resource.Annotations.Contains(verifier)) backend.Resource.Annotations.Add(verifier);
        verifier.Audience = audience;
        verifier.KeyIds.Add(keyId);
        var keyIndex = verifier.KeyIds.Count - 1;

        builder.WithEnvironment(context => WriteForwardedIdentitySigners(context, annotation, backend.Resource, pairing));
        backend.WithEnvironment(context => WriteVerifier(context, verifier, keyIndex, pairing));
        return builder;
    }

    static void ValidateForwardedIdentityNames(string audience, string keyId)
    {
        if (audience.Length is < 1 or > 128 || string.IsNullOrWhiteSpace(audience) || audience.Any(character => character is < ' ' or > '~'))
        {
            throw new InvalidForwardedIdentityAudience(audience);
        }
        if (keyId.Length is < 1 or > 64 || keyId.Any(character => !(character is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '_' or '-')))
        {
            throw new InvalidForwardedIdentityKeyId(keyId);
        }
    }

    static void ValidateForwardedIdentitySigningKey(ParameterResource? signingKey)
    {
        if (signingKey is { Secret: false })
        {
            throw new ArgumentException($"Signing key parameter '{signingKey.Name}' must be secret. Declare it with secret: true.", nameof(signingKey));
        }
    }

    static ForwardedIdentityVerifierAnnotation GetForwardedIdentityVerifier(IResource backend, string audience, string keyId)
    {
        var verifier = backend.Annotations.OfType<ForwardedIdentityVerifierAnnotation>().SingleOrDefault() ?? new();
        if (verifier.Audience is not null && !string.Equals(verifier.Audience, audience, StringComparison.Ordinal))
        {
            throw new ConflictingForwardedIdentityAudience(backend.Name, verifier.Audience, audience);
        }
        if (verifier.KeyIds.Contains(keyId, StringComparer.Ordinal))
        {
            throw new InvalidForwardedIdentityKeyId(keyId);
        }
        return verifier;
    }

    static IResourceBuilder<ParameterResource> CreateForwardedIdentityKey<T>(IResourceBuilder<T> builder, IResource backend)
        where T : IResourceWithEnvironment
    {
        if (!builder.ApplicationBuilder.ExecutionContext.IsRunMode)
        {
            throw new ForwardedIdentitySigningKeyNotProvisioned(backend.Name);
        }
        var secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        return builder.ApplicationBuilder.AddParameter($"{builder.Resource.Name}-{backend.Name}-signing-key", () => secret, publishValueAsDefault: false, secret: true);
    }

    static void WriteForwardedIdentitySigners(EnvironmentCallbackContext context, AuthProxyConfigAnnotation annotation, IResource backend, ForwardedIdentityPairing pairing)
    {
        foreach (var (serviceName, resource) in annotation.ServiceBackends)
        {
            if (ReferenceEquals(resource, backend)) WriteSigner(context, $"{ConfigPrefix}__Services__{serviceName}__ForwardedIdentity", pairing);
        }
        foreach (var (index, resource) in annotation.TenantListResources)
        {
            if (ReferenceEquals(resource, backend)) WriteSigner(context, $"{ConfigPrefix}__TenantResolutions__{index}__Options__ForwardedIdentity", pairing);
        }
    }

    static void WriteSigner(EnvironmentCallbackContext context, string prefix, ForwardedIdentityPairing pairing)
    {
        context.EnvironmentVariables[$"{prefix}__Audience"] = pairing.Audience;
        context.EnvironmentVariables[$"{prefix}__KeyId"] = pairing.KeyId;
        context.EnvironmentVariables[$"{prefix}__SecretBase64"] = pairing.Secret;
    }

    static void WriteVerifier(EnvironmentCallbackContext context, ForwardedIdentityVerifierAnnotation verifier, int index, ForwardedIdentityPairing pairing)
    {
        const string prefix = "Cratis__Arc__ForwardedIdentity";
        context.EnvironmentVariables["Cratis__Arc__TrustForwardedIdentityHeaders"] = bool.TrueString;
        context.EnvironmentVariables[$"{prefix}__Enabled"] = bool.TrueString;
        context.EnvironmentVariables[$"{prefix}__Audience"] = verifier.Audience!;
        context.EnvironmentVariables[$"{prefix}__Keys__{index}__KeyId"] = pairing.KeyId;
        context.EnvironmentVariables[$"{prefix}__Keys__{index}__SecretBase64"] = pairing.Secret;
    }
}
