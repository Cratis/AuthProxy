// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace E2E.OAuthGrantReceiver;

/// <summary>Independently verifies this lane's local ES256 issuer, not an AuthProxy principal.</summary>
sealed class AccessTokenVerifier(HttpClient client, string issuer)
{
    public async Task<VerifiedGrant> Verify(string authorization)
    {
        if (!authorization.StartsWith("Bearer ", StringComparison.Ordinal) || authorization.Contains(',')) throw new Rejected("bearer");
        var token = authorization[7..];
        var parts = token.Split('.');
        if (parts.Length != 3) throw new Rejected("bearer");
        ValidateHeader(parts[0]);
        using var keys = await client.GetFromJsonAsync<JsonDocument>($"{issuer}/jwks") ?? throw new Rejected("bearer");
        var key = keys.RootElement.GetProperty("keys")[0];
        VerifySignature(parts, key);
        using var payload = JsonDocument.Parse(Decode(parts[1]));
        ValidateClaims(payload.RootElement);
        return new(new("oauth-verifier", new(issuer, payload.RootElement.GetProperty("sub").GetString() ?? throw new Rejected("bearer"))), payload.RootElement.GetProperty("auth_time").GetInt64());
    }

    static void ValidateHeader(string encoded)
    {
        using var header = JsonDocument.Parse(Decode(encoded));
        if (header.RootElement.GetProperty("alg").GetString() != "ES256") throw new Rejected("algorithm");
        if (header.RootElement.GetProperty("kid").GetString() != "issuer-key") throw new Rejected("key-id");
        if (header.RootElement.GetProperty("typ").GetString() != "at+jwt") throw new Rejected("token-type");
    }

    static void VerifySignature(string[] parts, JsonElement key)
    {
        using var verifier = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = Decode(key.GetProperty("x").GetString()!), Y = Decode(key.GetProperty("y").GetString()!) }
        });
        if (!verifier.VerifyData(Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"), Decode(parts[2]), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) throw new Rejected("bearer");
    }

    void ValidateClaims(JsonElement claims)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (claims.GetProperty("iss").GetString() != issuer) throw new Rejected("issuer");
        if (claims.GetProperty("aud").GetString() != "grant-api") throw new Rejected("audience");
        if (claims.GetProperty("exp").GetInt64() <= now) throw new Rejected("expiry");
        if (claims.GetProperty("nbf").GetInt64() > now) throw new Rejected("not-before");
        if (claims.TryGetProperty("cnf", out _)) throw new Rejected("binding");
        if (claims.GetProperty("scope").GetString() != "grants.read") throw new Rejected("scope");
        if (claims.GetProperty("cid").GetString() != "00000000-0000-4000-8000-000000000348") throw new Rejected("credential");
    }

    public static byte[] Decode(string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
}
