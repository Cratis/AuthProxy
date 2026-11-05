// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Formats the Arc v1 signature envelope.</summary>
internal static class ForwardedIdentityEnvelope
{
    /// <summary>The sole Arc v1 proof header.</summary>
    internal const string Header = Headers.ForwardedIdentitySignature;

    /// <summary>Creates a fresh 256-bit base64url nonce.</summary>
    /// <returns>The nonce text.</returns>
    internal static string NewNonce() => Base64Url(RandomNumberGenerator.GetBytes(32));

    /// <summary>Computes the HMAC-SHA256 proof.</summary>
    /// <param name="secret">The shared key.</param>
    /// <param name="canonical">The framed canonical bytes.</param>
    /// <returns>The unpadded base64url MAC.</returns>
    internal static string Mac(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> canonical) => Base64Url(HMACSHA256.HashData(secret, canonical));

    /// <summary>Formats the five-part v1 envelope.</summary>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="timestamp">The Unix-seconds timestamp.</param>
    /// <param name="nonce">The nonce.</param>
    /// <param name="mac">The MAC.</param>
    /// <returns>The signature header value.</returns>
    internal static string Format(string keyId, string timestamp, string nonce, string mac) => $"v1.{keyId}.{timestamp}.{nonce}.{mac}";

    /// <summary>Encodes bytes as unpadded base64url.</summary>
    /// <param name="bytes">The input bytes.</param>
    /// <returns>The encoded bytes.</returns>
    internal static string Base64Url(ReadOnlySpan<byte> bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
