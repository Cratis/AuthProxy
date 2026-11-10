// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Numerics;
using System.Security.Cryptography;

namespace Cratis.AuthProxy.BearerRoutes.Dpop;

/// <summary>Verifies only ES256 public-JWK signatures and RFC 7638 thumbprints.</summary>
internal static class DpopPublicKey
{
    static readonly HashSet<string> _members = ["kty", "crv", "x", "y", "use", "key_ops", "alg"];
    static readonly BigInteger _prime = new(Convert.FromHexString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"), isUnsigned: true, isBigEndian: true);
    static readonly BigInteger _coefficient = new(Convert.FromHexString("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"), isUnsigned: true, isBigEndian: true);

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
        if (!OnCurve(point)) return false;
        using var key = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = point });
        thumbprint = DpopEncoding.Hash($"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}");
        return key.VerifyData(input, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    static bool OnCurve(ECPoint point)
    {
        if (point.X is not { Length: 32 } || point.Y is not { Length: 32 }) return false;
        var x = new BigInteger(point.X, isUnsigned: true, isBigEndian: true);
        var y = new BigInteger(point.Y, isUnsigned: true, isBigEndian: true);
        if (x >= _prime || y >= _prime) return false;
        var squared = y * y;
        var left = squared % _prime;
        var cubic = x * x * x;
        var right = (cubic - (3 * x) + _coefficient) % _prime;
        return left == right;
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
