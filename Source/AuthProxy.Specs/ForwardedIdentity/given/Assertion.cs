// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Cratis.AuthProxy.ForwardedIdentity.given;

/// <summary>
/// A forwarded-identity assertion taken apart the way a verifier takes it apart: three segments, the JSON of the
/// first two exactly as transmitted, and the raw signature.
/// </summary>
/// <param name="ProtectedHeader">The decoded JOSE header, byte for byte.</param>
/// <param name="Payload">The decoded claims, byte for byte.</param>
/// <param name="SigningInput">The first two segments, as signed.</param>
/// <param name="Signature">The raw IEEE P1363 signature.</param>
public sealed record Assertion(string ProtectedHeader, string Payload, string SigningInput, ReadOnlyMemory<byte> Signature)
{
    /// <summary>
    /// Gets the claim names in the order they were written.
    /// </summary>
    public IReadOnlyList<string> ClaimNames
    {
        get
        {
            using var document = JsonDocument.Parse(Payload);
            return [.. document.RootElement.EnumerateObject().Select(_ => _.Name)];
        }
    }

    /// <summary>
    /// Takes a compact JWS apart.
    /// </summary>
    /// <param name="token">The token.</param>
    /// <returns>The parts.</returns>
    public static Assertion Parse(string token)
    {
        var segments = token.Split('.');
        segments.Length.ShouldEqual(3);
        return new(
            Encoding.UTF8.GetString(Base64Url.DecodeFromChars(segments[0])),
            Encoding.UTF8.GetString(Base64Url.DecodeFromChars(segments[1])),
            $"{segments[0]}.{segments[1]}",
            Base64Url.DecodeFromChars(segments[2]));
    }

    /// <summary>
    /// Checks the signature with a public key.
    /// </summary>
    /// <param name="publicKeyPem">The EC P-256 public key.</param>
    /// <returns>Whether the signature verifies.</returns>
    public bool VerifiesWith(string publicKeyPem)
    {
        using var key = ECDsa.Create();
        key.ImportFromPem(publicKeyPem);
        return key.VerifyData(Encoding.ASCII.GetBytes(SigningInput), Signature.Span, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    /// <summary>
    /// Gets a string claim.
    /// </summary>
    /// <param name="name">The claim name.</param>
    /// <returns>The value, or <see langword="null"/> when the claim is absent.</returns>
    public string? Text(string name)
    {
        using var document = JsonDocument.Parse(Payload);
        return document.RootElement.TryGetProperty(name, out var value) ? value.GetString() : null;
    }

    /// <summary>
    /// Gets a numeric claim.
    /// </summary>
    /// <param name="name">The claim name.</param>
    /// <returns>The value.</returns>
    public long Number(string name)
    {
        using var document = JsonDocument.Parse(Payload);
        return document.RootElement.GetProperty(name).GetInt64();
    }
}
