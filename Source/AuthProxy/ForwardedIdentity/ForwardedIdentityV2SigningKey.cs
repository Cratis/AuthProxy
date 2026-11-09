// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Validates private ES256 material without retaining decoded private-key buffers.</summary>
static class ForwardedIdentityV2SigningKey
{
    static readonly string[] _p256Names = ["nistP256", "ECDSA_P256", "prime256v1", "secp256r1"];

    /// <summary>Validates version-specific material and retains only a public-key fingerprint for reuse detection.</summary>
    /// <param name="settings">The pinned v2 settings.</param>
    /// <param name="key">The validated public-key fingerprint.</param>
    /// <param name="problem">A safe configuration diagnostic.</param>
    /// <returns>Whether the configuration is usable.</returns>
    internal static bool TryCreate(ForwardedIdentitySigning settings, out ForwardedIdentitySigningKey? key, out string? problem)
    {
        key = null;
        problem = "ForwardedIdentity v2 requires a slug audience, valid key identifier and only strict base64 PKCS#8 P-256 private material (R6).";
        if (!TryOpen(settings, out var signer)) return false;
        using (signer)
        {
            key = new(settings.Audience, settings.KeyId, SHA256.HashData(signer!.ExportSubjectPublicKeyInfo())) { Version = "v2" };
        }
        problem = null;
        return true;
    }

    /// <summary>Checks non-secret settings before looking up a cached signer.</summary>
    /// <param name="settings">The pinned v2 settings.</param>
    /// <returns>Whether the metadata and material selection are valid.</returns>
    internal static bool IsValidSettings(ForwardedIdentitySigning settings) => settings.Version == "v2"
        && ForwardedIdentitySigningKey.IsValidAudience(settings.Audience) && ForwardedIdentitySigningKey.IsValidKeyId(settings.KeyId)
        && string.IsNullOrEmpty(settings.SecretBase64) && !string.IsNullOrEmpty(settings.PrivateKeyPkcs8Base64)
        && !settings.PrivateKeyPkcs8Base64.Any(char.IsWhiteSpace);

    /// <summary>Imports a single owned signing handle and clears the temporary private DER on every path.</summary>
    /// <param name="settings">The pinned v2 settings.</param>
    /// <param name="signer">The owned signing handle, which the caller must dispose.</param>
    /// <returns>Whether strict P-256 private material was imported.</returns>
    internal static bool TryOpen(ForwardedIdentitySigning settings, out ECDsa? signer)
    {
        signer = null;
        if (!IsValidSettings(settings)) return false;
        byte[] bytes = [];
        ECDsa? imported = null;
        try
        {
            bytes = Convert.FromBase64String(settings.PrivateKeyPkcs8Base64);
            if (!IsCanonicalBase64(bytes, settings.PrivateKeyPkcs8Base64)) return false;
            imported = ECDsa.Create();
            imported.ImportPkcs8PrivateKey(bytes, out var read);
            if (read != bytes.Length || !IsP256(imported.ExportParameters(false).Curve.Oid)) return false;
            signer = imported;
            imported = null;
            return true;
        }
        catch (Exception error) when (error is CryptographicException or FormatException or ArgumentException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            imported?.Dispose();
        }
    }

    /// <summary>Recognizes platform representations of the named P-256 curve.</summary>
    /// <param name="oid">The exported curve identifier.</param>
    /// <returns>Whether the identifier is P-256.</returns>
    internal static bool IsP256(Oid oid) => oid.Value is { } value ? value == "1.2.840.10045.3.1.7" : _p256Names.Contains(oid.FriendlyName, StringComparer.Ordinal);

    static bool IsCanonicalBase64(byte[] bytes, string value)
    {
        var characters = new char[value.Length];
        try
        {
            return Convert.TryToBase64Chars(bytes, characters, out var written) && written == value.Length && value.AsSpan().SequenceEqual(characters);
        }
        finally
        {
            characters.AsSpan().Clear();
        }
    }
}
