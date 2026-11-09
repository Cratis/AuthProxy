// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Validates and normalizes private ES256 key material.</summary>
static class ForwardedIdentityV2SigningKey
{
    /// <summary>Validates version-specific material without putting it in diagnostics.</summary>
    /// <param name="settings">The pinned v2 settings.</param>
    /// <param name="key">The normalized private signing key.</param>
    /// <param name="problem">A safe configuration diagnostic.</param>
    /// <returns>Whether the configuration is usable.</returns>
    internal static bool TryCreate(ForwardedIdentitySigning settings, out ForwardedIdentitySigningKey? key, out string? problem)
    {
        key = null;
        problem = "ForwardedIdentity v2 requires a slug audience, valid key identifier and only strict base64 PKCS#8 P-256 private material (R6).";
        if (!ForwardedIdentitySigningKey.IsValidAudience(settings.Audience) || !ForwardedIdentitySigningKey.IsValidKeyId(settings.KeyId)
            || !string.IsNullOrEmpty(settings.SecretBase64) || string.IsNullOrEmpty(settings.PrivateKeyPkcs8Base64)
            || settings.PrivateKeyPkcs8Base64.Any(char.IsWhiteSpace))
        {
            return false;
        }

        try
        {
            var bytes = Convert.FromBase64String(settings.PrivateKeyPkcs8Base64);
            if (Convert.ToBase64String(bytes) != settings.PrivateKeyPkcs8Base64) return false;
            using var signer = ECDsa.Create();
            signer.ImportPkcs8PrivateKey(bytes, out var read);
            if (read != bytes.Length || signer.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7") return false;
            key = new(settings.Audience, settings.KeyId, signer.ExportPkcs8PrivateKey()) { Version = "v2" };
            problem = null;
            return true;
        }
        catch (Exception error) when (error is CryptographicException or FormatException or ArgumentException)
        {
            return false;
        }
    }
}
