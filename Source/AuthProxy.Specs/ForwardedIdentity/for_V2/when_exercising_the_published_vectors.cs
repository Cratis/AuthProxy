// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Cratis.AuthProxy.ForwardedIdentity.for_V2;

public class when_exercising_the_published_vectors : Specification
{
    [Fact]
    public void should_reproduce_and_sign_every_accept_case()
    {
        using var fixture = V2Vector.Load();
        foreach (var vector in fixture.RootElement.GetProperty("cases").EnumerateArray().Where(vector => vector.GetProperty("expected").GetProperty("result").GetString() == "accept"))
        {
            var parts = vector.GetProperty("envelope").GetString()!.Split('.');
            Assert.True(V2Vector.Canonical(vector, parts, out var canonical), vector.GetProperty("name").GetString());
            Assert.Equal(vector.GetProperty("signingInput").GetString(), Encoding.UTF8.GetString(canonical));
            var key = Key(fixture.RootElement, parts[1]);
            using var signer = ECDsa.Create();
            signer.ImportFromPem(key.GetProperty("privateKeyPem").GetString());
            var proof = ForwardedIdentityV2Envelope.Sign(signer.ExportPkcs8PrivateKey(), parts[1], parts[2], parts[3], canonical);
            var signature = Decode(proof.Split('.')[4]);
            Assert.Equal(64, signature.Length);
            using var verifier = ECDsa.Create();
            verifier.ImportFromPem(key.GetProperty("publicKeyPem").GetString());
            Assert.True(verifier.VerifyData(canonical, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        }
    }

    [Fact]
    public void should_conform_to_all_220_reference_outcomes()
    {
        using var fixture = V2Vector.Load();
        var vectors = fixture.RootElement.GetProperty("cases").EnumerateArray().ToArray();
        Assert.Equal(220, vectors.Length);
        var reservations = new HashSet<(string Group, string Audience, string Key, string Nonce)>();
        foreach (var vector in vectors)
        {
            var accepted = Accept(vector, fixture.RootElement, reservations);
            Assert.True(accepted == (vector.GetProperty("expected").GetProperty("result").GetString() == "accept"), vector.GetProperty("name").GetString());
        }
    }

    [Fact]
    public void should_refuse_every_producer_applicable_rejection()
    {
        using var fixture = V2Vector.Load();
        foreach (var vector in fixture.RootElement.GetProperty("cases").EnumerateArray())
        {
            var reason = vector.GetProperty("expected").GetProperty("reason").GetString();
            if (reason is not ("headers" or "bounds" or "request" or "metadata" or "identity" or "credential")) continue;
            var parts = vector.GetProperty("envelope").GetString()!.Split('.');
            var input = vector.GetProperty("inputs");
            using var request = V2Vector.Request(input);
            var context = V2Vector.Context(input);
            var canSign = V2Vector.Canonical(vector, parts, out _) && ForwardedIdentityV2ContextHeaders.Matches(request, context);
            Assert.False(canSign, vector.GetProperty("name").GetString());
        }
    }

    static bool Accept(JsonElement vector, JsonElement fixture, HashSet<(string Group, string Audience, string Key, string Nonce)> reservations)
    {
        // Test-only consumer: transport, freshness and replay remain receiver duties.
        var input = vector.GetProperty("inputs");
        if (!input.GetProperty("authenticatedTls").GetBoolean()) return false;
        var envelope = vector.GetProperty("envelope").GetString()!;
        var parts = envelope.Split('.');
        if (envelope.Length is 0 or > 256 || envelope.Any(character => character <= 32 || character >= 127)
            || parts.Length != 5 || parts[0] != "v2" || !ForwardedIdentitySigningKey.IsValidKeyId(parts[1])
            || !ForwardedIdentityV2Envelope.IsTimestamp(parts[2]) || !ForwardedIdentityV2Envelope.IsBase64Url(parts[3], 16) || !ForwardedIdentityV2Envelope.IsBase64Url(parts[4], 64))
        {
            return false;
        }
        var timestamp = long.Parse(parts[2], CultureInfo.InvariantCulture);
        var now = input.GetProperty("now").GetInt64();
        if (timestamp < (decimal)now - 60 || timestamp > (decimal)now + 30) return false;
        var key = Key(fixture, parts[1]);
        if (key.ValueKind == JsonValueKind.Undefined || !V2Vector.Canonical(vector, parts, out var canonical)) return false;
        using var verifier = ECDsa.Create();
        verifier.ImportFromPem(key.GetProperty("publicKeyPem").GetString());
        try
        {
            if (!verifier.VerifyData(canonical, Decode(parts[4]), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
        using var request = V2Vector.Request(input);
        if (!ForwardedIdentityV2ContextHeaders.Matches(request, V2Vector.Context(input))) return false;
        if (!input.GetProperty("replaySensitive").GetBoolean()) return true;
        if (!input.GetProperty("storeAvailable").GetBoolean() || input.GetProperty("storeFull").GetBoolean()) return false;
        return !vector.TryGetProperty("replayGroup", out var group) || group.ValueKind == JsonValueKind.Null
            || reservations.Add((group.GetString()!, input.GetProperty("aud").GetString()!, parts[1], parts[3]));
    }

    static JsonElement Key(JsonElement fixture, string keyId) => fixture.GetProperty("testKeys").EnumerateArray().FirstOrDefault(key => key.GetProperty("keyIds").EnumerateArray().Any(id => id.GetString() == keyId));
    static byte[] Decode(string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - (value.Length % 4)) % 4));
}
