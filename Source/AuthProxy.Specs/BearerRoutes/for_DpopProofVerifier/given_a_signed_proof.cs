// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cratis.AuthProxy.BearerRoutes.Dpop;

namespace Cratis.AuthProxy.BearerRoutes.for_DpopProofVerifier;

public class given_a_signed_proof : Specification
{
    protected const long Now = 2000000000;
    protected const string Token = "synthetic-access-token";
    protected const string Target = "https://api.example.test/mcp";
    protected ECDsa Key;
    protected Dictionary<string, object> Header;
    protected Dictionary<string, object> Payload;
    protected string Jkt;

    void Establish()
    {
        Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var point = Key.ExportParameters(false).Q;
        var x = Encode(point.X!);
        var y = Encode(point.Y!);
        var jwk = new Dictionary<string, object> { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = x, ["y"] = y };
        Header = new() { ["typ"] = "dpop+jwt", ["alg"] = "ES256", ["jwk"] = jwk };
        Payload = new() { ["htm"] = "POST", ["htu"] = Target, ["iat"] = Now, ["jti"] = Guid.NewGuid().ToString(), ["ath"] = Encode(SHA256.HashData(Encoding.ASCII.GetBytes(Token))) };
        Jkt = Encode(SHA256.HashData(Encoding.UTF8.GetBytes($"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}")));
    }

    void Destroy() => Key.Dispose();

    protected string Proof(string? header = null, string? payload = null)
    {
        var input = Encode(Encoding.UTF8.GetBytes(header ?? JsonSerializer.Serialize(Header))) + "." + Encode(Encoding.UTF8.GetBytes(payload ?? JsonSerializer.Serialize(Payload)));
        return input + "." + Encode(Key.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    private protected DpopProofResult Verify(string? proof = null, long now = Now) => DpopProofVerifier.Verify(proof ?? Proof(), new("POST", Target, Token, Jkt, now));
    protected static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
