// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Represents validated v1 signing material.</summary>
/// <param name="Audience">The receiving audience.</param>
/// <param name="KeyId">The public key identifier.</param>
/// <param name="Secret">The 32-byte shared secret.</param>
public sealed record ForwardedIdentitySigningKey(string Audience, string KeyId, ReadOnlyMemory<byte> Secret)
{
    /// <summary>Gets the pinned wire version; the key bytes hold PKCS#8 private material for v2.</summary>
    public string Version { get; init; } = "v1";

    /// <summary>Validates signing settings without exposing secret material in diagnostics.</summary>
    /// <param name="settings">The configured settings.</param>
    /// <param name="key">The validated key, when successful.</param>
    /// <param name="problem">The violated configuration rule, when unsuccessful.</param>
    /// <returns>Whether the settings are usable.</returns>
    public static bool TryCreate(ForwardedIdentitySigning settings, out ForwardedIdentitySigningKey? key, out string? problem)
    {
        key = null;
        problem = null;
        if (settings.Version == "v2") return ForwardedIdentityV2SigningKey.TryCreate(settings, out key, out problem);
        if (settings.Version != "v1" || !string.IsNullOrEmpty(settings.PrivateKeyPkcs8Base64))
        {
            problem = "ForwardedIdentity requires an explicit supported version and matching key material (R5).";
            return false;
        }
        if (string.IsNullOrWhiteSpace(settings.Audience) || settings.Audience.Length > 128 || settings.Audience.Any(character => character is < ' ' or > '~'))
        {
            problem = "ForwardedIdentity:Audience must be 1–128 printable ASCII characters and not blank (R1).";
            return false;
        }
        if (string.IsNullOrEmpty(settings.KeyId) || settings.KeyId.Length > 64 || settings.KeyId.Any(character => character is not (>= 'a' and <= 'z') and not (>= 'A' and <= 'Z') and not (>= '0' and <= '9') and not '_' and not '-'))
        {
            problem = "ForwardedIdentity:KeyId must match [A-Za-z0-9_-]{1,64} (R2).";
            return false;
        }
        var secret = new byte[32];
        if (string.IsNullOrEmpty(settings.SecretBase64) || settings.SecretBase64.Any(char.IsWhiteSpace) ||
            !Convert.TryFromBase64String(settings.SecretBase64, secret, out var written) || written != secret.Length ||
            !string.Equals(Convert.ToBase64String(secret), settings.SecretBase64, StringComparison.Ordinal))
        {
            problem = "ForwardedIdentity:SecretBase64 must be strict standard base64 encoding exactly 32 bytes (R3).";
            return false;
        }
        if (CryptographicOperations.FixedTimeEquals(secret, Enumerable.Range(0, 32).Select(value => (byte)value).ToArray()))
        {
            problem = "ForwardedIdentity:SecretBase64 must not use the published test key (R4).";
            return false;
        }
        key = new(settings.Audience, settings.KeyId, secret);
        return true;
    }

    /// <inheritdoc/>
    public override string ToString() => $"Audience = {Audience}, KeyId = {KeyId}";

    /// <summary>Checks the v2 application slug grammar.</summary>
    /// <param name="value">The audience.</param>
    /// <returns>Whether it is an unambiguous bounded slug.</returns>
    internal static bool IsValidAudience(string value) => value.Length is >= 1 and <= 64 && value[0] is >= 'a' and <= 'z'
        && value.All(character => character is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-') && value.Split('-').All(segment => segment.Length > 0);

    /// <summary>Checks the bounded envelope key identifier grammar.</summary>
    /// <param name="value">The key identifier.</param>
    /// <returns>Whether it is valid.</returns>
    internal static bool IsValidKeyId(string value) => value.Length is >= 1 and <= 64 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '_' or '-');
}
