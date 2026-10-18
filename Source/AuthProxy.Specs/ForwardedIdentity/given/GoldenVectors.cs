// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;

namespace Cratis.AuthProxy.ForwardedIdentity.given;

/// <summary>
/// The committed golden vectors of the forwarded-identity assertion, shared byte for byte with the verifier.
/// </summary>
/// <param name="PrivateKeyPem">The EC P-256 private key the token was produced with.</param>
/// <param name="PublicKeyPem">The matching public key.</param>
/// <param name="KeyId">The key identifier.</param>
/// <param name="Issuer">The issuer.</param>
/// <param name="Audience">The audience.</param>
/// <param name="IssuedAt">The issue time, in seconds since the Unix epoch.</param>
/// <param name="LifetimeSeconds">The lifetime, in seconds.</param>
/// <param name="Jti">The assertion identifier.</param>
/// <param name="Method">The request method.</param>
/// <param name="Path">The request path.</param>
/// <param name="Headers">The request headers, in the order they were set.</param>
/// <param name="Canonical">The expected canonical header string.</param>
/// <param name="Fwh">The expected header digest.</param>
/// <param name="ProtectedHeader">The expected JOSE header JSON.</param>
/// <param name="Payload">The expected claims JSON.</param>
/// <param name="SigningInput">The expected signing input.</param>
/// <param name="Token">A complete token produced with the private key.</param>
public sealed record GoldenVectors(
    string PrivateKeyPem,
    string PublicKeyPem,
    string KeyId,
    string Issuer,
    string Audience,
    long IssuedAt,
    long LifetimeSeconds,
    string Jti,
    string Method,
    string Path,
    IReadOnlyList<GoldenVectorHeader> Headers,
    string Canonical,
    string Fwh,
    string ProtectedHeader,
    string Payload,
    string SigningInput,
    string Token)
{
    static readonly JsonSerializerOptions _options = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// Loads the committed vectors.
    /// </summary>
    /// <returns>The vectors.</returns>
    public static GoldenVectors Load()
    {
        var path = System.IO.Path.Combine(AppContext.BaseDirectory, "ForwardedIdentity", "golden-vectors.json");
        return JsonSerializer.Deserialize<GoldenVectors>(File.ReadAllText(path), _options)!;
    }

    /// <summary>
    /// Builds the request the vectors describe.
    /// </summary>
    /// <returns>The request.</returns>
    public HttpRequestMessage Request()
    {
        var request = new HttpRequestMessage(new HttpMethod(Method), $"https://reports.internal{Path}?page=2");
        foreach (var header in Headers)
        {
            request.Headers.TryAddWithoutValidation(header.Name, header.Value);
        }

        return request;
    }
}
