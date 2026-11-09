// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.Security.Cryptography;

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>The unambiguous ES256 v2 wire envelope, never a v1 HMAC.</summary>
public static class ForwardedIdentityV2Envelope
{
    /// <summary>Signs canonical input with P-256 in IEEE P1363 r || s form.</summary>
    /// <param name="privateKey">A PKCS#8 encoded P-256 private key.</param>
    /// <param name="keyId">The configured key identifier.</param>
    /// <param name="timestamp">The canonical unsigned Unix timestamp.</param>
    /// <param name="nonce">A fresh canonical 16-byte base64url nonce.</param>
    /// <param name="canonical">The v2 canonical input.</param>
    /// <returns>The single versioned signature header.</returns>
    /// <exception cref="ArgumentException">The envelope fields are invalid.</exception>
    /// <exception cref="CryptographicException">The key is not valid P-256 private material.</exception>
    public static string Sign(byte[] privateKey, string keyId, string timestamp, string nonce, byte[] canonical)
    {
        if (!ForwardedIdentitySigningKey.IsValidKeyId(keyId) || !IsTimestamp(timestamp) || !IsBase64Url(nonce, 16)) throw new ArgumentException("Invalid v2 envelope fields.");
        using var signer = ECDsa.Create();
        signer.ImportPkcs8PrivateKey(privateKey, out var read);
        if (read != privateKey.Length || !ForwardedIdentityV2SigningKey.IsP256(signer.ExportParameters(false).Curve.Oid)) throw new CryptographicException("A P-256 private key is required.");
        return Sign(signer, keyId, timestamp, nonce, canonical);
    }

    /// <summary>Signs using an owned, already validated P-256 handle.</summary>
    /// <param name="signer">The caller-synchronized P-256 signing handle.</param>
    /// <param name="keyId">The configured key identifier.</param>
    /// <param name="timestamp">The issuance timestamp.</param>
    /// <param name="nonce">The fresh 16-byte nonce.</param>
    /// <param name="canonical">The bounded canonical bytes.</param>
    /// <returns>The v2 envelope.</returns>
    /// <exception cref="ArgumentException">The envelope fields are invalid.</exception>
    internal static string Sign(ECDsa signer, string keyId, string timestamp, string nonce, byte[] canonical)
    {
        if (!ForwardedIdentitySigningKey.IsValidKeyId(keyId) || !IsTimestamp(timestamp) || !IsBase64Url(nonce, 16)) throw new ArgumentException("Invalid v2 envelope fields.");
        var signature = signer.SignData(canonical, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return $"v2.{keyId}.{timestamp}.{nonce}.{Encode(signature)}";
    }

    /// <summary>Encodes bytes as canonical unpadded base64url.</summary>
    /// <param name="value">The bytes to encode.</param>
    /// <returns>The canonical encoding.</returns>
    internal static string Encode(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Checks canonical unsigned int64 timestamp text.</summary>
    /// <param name="value">The timestamp.</param>
    /// <returns>Whether the text is canonical.</returns>
    internal static bool IsTimestamp(string value) => long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var number) && value == number.ToString(CultureInfo.InvariantCulture);

    /// <summary>Checks base64url length, alphabet and pad bits by round-tripping.</summary>
    /// <param name="value">The encoded text.</param>
    /// <param name="size">The required decoded byte count.</param>
    /// <returns>Whether the text is canonical.</returns>
    internal static bool IsBase64Url(string value, int size)
    {
        if (value.Length != ((size * 8) + 5) / 6 || value.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not ('-' or '_'))) return false;
        try
        {
            var bytes = Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - (value.Length % 4)) % 4));
            return bytes.Length == size && Encode(bytes) == value;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
