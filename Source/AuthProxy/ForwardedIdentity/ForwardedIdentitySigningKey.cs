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
    /// <summary>Validates signing settings without exposing secret material in diagnostics.</summary>
    /// <param name="settings">The configured settings.</param>
    /// <param name="key">The validated key, when successful.</param>
    /// <param name="problem">The violated configuration rule, when unsuccessful.</param>
    /// <returns>Whether the settings are usable.</returns>
    public static bool TryCreate(ForwardedIdentitySigning settings, out ForwardedIdentitySigningKey? key, out string? problem)
    {
        key = null;
        problem = null;
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
}
