// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace E2E.Issuer;

sealed class LocalIssuer : IDisposable
{
    public const string Address = "https://issuer:8443";
    public const string Subject = "00000000-0000-4000-8000-000000000347";
    public const string Credential = "00000000-0000-4000-8000-000000000348";
    readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    readonly ConcurrentDictionary<string, bool> _tokens = new(StringComparer.Ordinal);
    int _outage;

    public bool Outage { get => Volatile.Read(ref _outage) != 0; set => Interlocked.Exchange(ref _outage, value ? 1 : 0); }

    public object Jwks()
    {
        var key = _key.ExportParameters(false);
        return new { keys = new[] { new { kty = "EC", crv = "P-256", kid = "issuer-key", use = "sig", alg = "ES256", x = Url(key.Q.X!), y = Url(key.Q.Y!) } } };
    }

    public string Mint(string scenario)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var claims = new Dictionary<string, object>
        {
            ["iss"] = scenario == "wrong-issuer" ? "https://not-the-issuer.invalid" : Address,
            ["aud"] = scenario == "wrong-audience" ? "other-api" : "grant-api",
            ["sub"] = Subject,
            ["name"] = "Grant Person",
            ["preferred_username"] = "grant-person",
            ["client_id"] = "local-client",
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["iat"] = scenario == "expired" ? now - 600 : now,
            ["nbf"] = scenario == "expired" ? now - 600 : now - 1,
            ["exp"] = scenario == "expired" ? now - 300 : now + 300,
            ["scope"] = scenario == "wrong-scope" ? "other.read" : "grants.read",
            ["auth_time"] = now,
            ["idp"] = "local-issuer",
            ["acr"] = "basic",
            ["amr"] = new[] { "pwd" },
            ["cid"] = Credential,
            ["cratis/tenant"] = "4f1d2c1e-6f1b-4d3b-9a46-5e2f2a7a2b10"
        };
        if (scenario == "bound") claims["cnf"] = new { jkt = Url(RandomNumberGenerator.GetBytes(32)) };
        if (scenario == "actor") claims["act"] = new { iss = Address, sub = "local-client" };
        var input = $"{Url(JsonSerializer.SerializeToUtf8Bytes(new { alg = "ES256", typ = scenario == "wrong-type" ? "JWT" : "at+jwt", kid = "issuer-key" }))}.{Url(JsonSerializer.SerializeToUtf8Bytes(claims))}";
        byte[] signature;
        lock (_key) signature = _key.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var token = $"{input}.{Url(signature)}";
        _tokens[token] = true;
        return token;
    }

    public object Introspect(string token) => _tokens.TryGetValue(token, out var active) && active
        ? new Dictionary<string, object> { ["active"] = true, ["iss"] = Address, ["sub"] = Subject, ["client_id"] = "local-client", ["credential_kind"] = "oauth-grant", ["credential_id"] = Credential, ["cache_epoch"] = "7", ["exp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 300 }
        : new { active = false };

    public void Revoke(string token) => _tokens[token] = false;
    public void Dispose() => _key.Dispose();
    static string Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
