// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// The signed forwarding assertion an origin received, taken apart the way a verifying backend takes it apart.
/// </summary>
/// <param name="Token">The compact JWS as received.</param>
/// <param name="ProtectedHeader">The decoded JOSE header.</param>
/// <param name="Payload">The decoded claims.</param>
public sealed record ForwardedAssertion(string Token, string ProtectedHeader, string Payload)
{
    /// <summary>
    /// Reads the assertion a forwarded request carries.
    /// </summary>
    /// <param name="request">The request as the origin received it.</param>
    /// <returns>The assertion, or <see langword="null"/> when the request carried none or it is not a compact JWS.</returns>
    public static ForwardedAssertion? From(ForwardedRequest? request)
    {
        var token = request?.Value(Headers.ForwardedIdentity);
        if (string.IsNullOrEmpty(token))
        {
            return null;
        }

        var segments = token.Split('.');
        if (segments.Length != 3)
        {
            return null;
        }

        return new(
            token,
            Encoding.UTF8.GetString(Base64Url.DecodeFromChars(segments[0])),
            Encoding.UTF8.GetString(Base64Url.DecodeFromChars(segments[1])));
    }

    /// <summary>
    /// Checks the signature with the public key a backend pinned.
    /// </summary>
    /// <param name="publicKeyPem">The EC P-256 public key.</param>
    /// <returns>Whether the signature verifies.</returns>
    public bool VerifiesWith(string publicKeyPem)
    {
        var segments = Token.Split('.');
        using var key = ECDsa.Create();
        key.ImportFromPem(publicKeyPem);
        return key.VerifyData(
            Encoding.ASCII.GetBytes($"{segments[0]}.{segments[1]}"),
            Base64Url.DecodeFromChars(segments[2]),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    /// <summary>
    /// Gets a string member of the JOSE header.
    /// </summary>
    /// <param name="name">The member name.</param>
    /// <returns>The value, or <see langword="null"/> when absent.</returns>
    public string? HeaderValue(string name) => StringMember(ProtectedHeader, name);

    /// <summary>
    /// Gets a string claim.
    /// </summary>
    /// <param name="name">The claim name.</param>
    /// <returns>The value, or <see langword="null"/> when absent.</returns>
    public string? Claim(string name) => StringMember(Payload, name);

    static string? StringMember(string json, string name)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.TryGetProperty(name, out var value) ? value.GetString() : null;
    }
}
