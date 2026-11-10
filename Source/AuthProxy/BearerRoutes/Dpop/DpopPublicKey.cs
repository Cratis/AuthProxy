// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;

namespace Cratis.AuthProxy.BearerRoutes.Dpop;

/// <summary>Verifies only ES256 public-JWK signatures and RFC 7638 thumbprints.</summary>
internal static class DpopPublicKey
{
    static readonly HashSet<string> _members = ["kty", "crv", "x", "y", "use", "key_ops", "alg"];

    /// <summary>Verifies a P-256 public point without private or remote key material.</summary>
    /// <param name="header">The unique JOSE header.</param>
    /// <param name="input">The compact signing input.</param>
    /// <param name="signature">The decoded signature.</param>
    /// <param name="thumbprint">The canonical public-key thumbprint.</param>
    /// <returns>Whether the signature and key policy verify.</returns>
    internal static bool Verify(JsonElement header, byte[] input, byte[] signature, out string thumbprint)
    {
        thumbprint = string.Empty;
        if (DpopEncoding.Text(header, "alg") != "ES256" || signature.Length != 64) return false;
        if (!header.TryGetProperty("jwk", out var jwk) || !Valid(jwk)) return false;
        var x = DpopEncoding.Text(jwk, "x") ?? string.Empty;
        var y = DpopEncoding.Text(jwk, "y") ?? string.Empty;
        var point = new ECPoint { X = DpopEncoding.Decode(x), Y = DpopEncoding.Decode(y) };
        if (point.X.Length != 32 || point.Y.Length != 32) return false;
        using var key = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = point });
        thumbprint = DpopEncoding.Hash($"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}");
        return key.VerifyData(input, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    static bool Valid(JsonElement jwk) =>
        jwk.ValueKind == JsonValueKind.Object
        && jwk.EnumerateObject().All(property => _members.Contains(property.Name))
        && DpopEncoding.Text(jwk, "kty") == "EC"
        && DpopEncoding.Text(jwk, "crv") == "P-256"
        && OptionalText(jwk, "use", "sig") && OptionalText(jwk, "alg", "ES256") && VerifyOperation(jwk);

    static bool OptionalText(JsonElement jwk, string name, string expected) => !jwk.TryGetProperty(name, out _) || DpopEncoding.Text(jwk, name) == expected;

    static bool VerifyOperation(JsonElement jwk)
    {
        if (!jwk.TryGetProperty("key_ops", out var operations)) return true;
        return operations.ValueKind == JsonValueKind.Array
            && operations.EnumerateArray().All(value => value.ValueKind == JsonValueKind.String)
            && operations.EnumerateArray().Any(value => value.GetString() == "verify");
    }
}
