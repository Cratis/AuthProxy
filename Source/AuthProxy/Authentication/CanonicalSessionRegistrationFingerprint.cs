// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.WebUtilities;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Creates opaque, versioned fingerprints that bind canonical sessions to their static provider registration.
/// </summary>
internal static class CanonicalSessionRegistrationFingerprint
{
    /// <summary>
    /// The authentication-properties item key that stores the canonical provider registration fingerprint.
    /// </summary>
    internal const string StateKey = "Cratis.AuthProxy.CanonicalSessionRegistration";

    const string Domain = "Cratis.AuthProxy.CanonicalSessionRegistrationFingerprint";
    const string Version = "1";
    const string ValuePrefix = "v1:";

    /// <summary>
    /// Creates a fingerprint for an OIDC provider from its configuration and effective named handler options.
    /// </summary>
    /// <param name="scheme">The derived authentication scheme.</param>
    /// <param name="provider">The provider registration.</param>
    /// <param name="options">The effective OIDC handler options.</param>
    /// <returns>The opaque version-one registration fingerprint.</returns>
    internal static string Create(string scheme, C.OidcProvider provider, OpenIdConnectOptions options) => Create(
        "oidc",
        scheme,
        provider.CanonicalIdentity!.ProviderKey,
        provider.CanonicalIdentity.SubjectClaimType,
        provider.ClientId,
        options.ClientId,
        provider.Authority,
        options.MetadataAddress);

    /// <summary>
    /// Creates a fingerprint for an OAuth provider from its configuration and effective named handler options.
    /// </summary>
    /// <param name="scheme">The derived authentication scheme.</param>
    /// <param name="provider">The provider registration.</param>
    /// <param name="options">The effective OAuth handler options.</param>
    /// <returns>The opaque version-one registration fingerprint.</returns>
    internal static string Create(string scheme, C.OAuthProvider provider, OAuthOptions options)
    {
        CanonicalIssuer.TryNormalize(provider.CanonicalIdentity!.Issuer, out var issuer);
        var fields = new List<string?>
        {
            "oauth",
            scheme,
            provider.CanonicalIdentity.ProviderKey,
            provider.CanonicalIdentity.SubjectClaimType,
            provider.ClientId,
            options.ClientId,
            issuer,
            provider.AuthorizationEndpoint,
            provider.TokenEndpoint,
            provider.UserInformationEndpoint,
            options.AuthorizationEndpoint,
            options.TokenEndpoint,
            options.UserInformationEndpoint
        };

        foreach (var mapping in provider.ClaimMappings.OrderBy(_ => _.Key, StringComparer.Ordinal))
        {
            fields.Add(mapping.Key);
            fields.Add(mapping.Value);
        }

        return Create([.. fields]);
    }

    /// <summary>
    /// Determines whether a stored value has the exact supported version and digest encoding.
    /// </summary>
    /// <param name="value">The stored fingerprint value.</param>
    /// <returns><see langword="true"/> when the value is a well-formed version-one fingerprint; otherwise <see langword="false"/>.</returns>
    internal static bool IsWellFormed(string? value)
    {
        if (value?.StartsWith(ValuePrefix, StringComparison.Ordinal) != true)
        {
            return false;
        }

        try
        {
            return WebEncoders.Base64UrlDecode(value[ValuePrefix.Length..]).Length == SHA256.HashSizeInBytes;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    static string Create(params string?[] fields)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Append(hash, Domain);
        Append(hash, Version);
        foreach (var field in fields)
        {
            Append(hash, field);
        }

        return $"{ValuePrefix}{WebEncoders.Base64UrlEncode(hash.GetHashAndReset())}";
    }

    static void Append(IncrementalHash hash, string? value)
    {
        Span<byte> length = stackalloc byte[sizeof(int)];
        if (value is null)
        {
            BinaryPrimitives.WriteInt32BigEndian(length, -1);
            hash.AppendData(length);
            return;
        }

        var bytes = Encoding.UTF8.GetBytes(value);
        BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
        hash.AppendData(length);
        hash.AppendData(bytes);
    }
}
