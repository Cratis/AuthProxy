// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteMiddleware;

internal sealed class PublishedDpopProof : IDisposable
{
    readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    readonly string _jti = Guid.NewGuid().ToString();

    public void Dispose() => _key.Dispose();

    internal object Jwk
    {
        get
        {
            var point = _key.ExportParameters(false).Q;
            return new { kty = "EC", crv = "P-256", x = Encode(point.X!), y = Encode(point.Y!) };
        }
    }

    internal string Jkt
    {
        get
        {
            var point = _key.ExportParameters(false).Q;
            return Hash($"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{Encode(point.X!)}\",\"y\":\"{Encode(point.Y!)}\"}}");
        }
    }

    internal string Sign(string token, string path, string id)
    {
        var payload = new
        {
            jti = _jti,
            iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - (id == "dpop-requires-fresh-iat" ? 301 : 0),
            htu = "https://direct.example.test" + (id == "dpop-requires-matching-target" ? "/wrong-target" : path),
            htm = id == "dpop-requires-matching-method" ? "POST" : "GET",
            ath = Hash(id == "dpop-requires-matching-token-hash" ? "different-synthetic-token" : token),
        };
        var input = Encode(JsonSerializer.SerializeToUtf8Bytes(new { typ = "dpop+jwt", alg = "ES256", jwk = Jwk })) + "." + Encode(JsonSerializer.SerializeToUtf8Bytes(payload));
        return input + "." + Encode(_key.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    static string Hash(string value) => Encode(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
