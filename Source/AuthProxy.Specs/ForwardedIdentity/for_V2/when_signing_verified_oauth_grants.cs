// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.ForwardedIdentity.for_V2;

public class when_signing_verified_oauth_grants : Specification
{
    const string Token = "verified-token-not-a-pat";

    [Fact]
    public void should_sign_the_raw_token_hash_without_the_bearer_prefix_and_verify_the_envelope()
    {
        using var fixture = V2Vector.Load();
        var input = fixture.RootElement.GetProperty("cases")[0].GetProperty("inputs");
        using var request = V2Vector.Request(input);
        var context = Context(input);
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + Token);
        request.Options.Set(ForwardedIdentityTrustedContext.OptionsKey, context);
        var settings = when_signing_with_explicit_trusted_context.Settings();
        settings.TenantHeader = context.TenantHeader;
        using var signer = when_signing_with_explicit_trusted_context.Signer(settings);
        Assert.Equal(ForwardedIdentitySigningOutcome.SignatureCreated, signer.Sign(request, when_signing_with_explicit_trusted_context.Target()));
        var hash = request.Headers.GetValues("x-cratis-forwarded-token-sha256").Single();
        Assert.Equal(Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(Token))), hash);
        Assert.NotEqual(Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes("Bearer " + Token))), hash);
        Assert.Equal("Bearer " + Token, request.Headers.GetValues("Authorization").Single());
        Assert.Equal("oauth-grant", request.Headers.GetValues("x-cratis-credential-kind").Single());
        Assert.Equal("grant-record", request.Headers.GetValues("x-cratis-credential-id").Single());
        Assert.False(request.Headers.Contains("x-cratis-act"));
        Assert.False(request.Headers.Contains("x-cratis-grant-id"));
        var parts = request.Headers.GetValues(Headers.ForwardedIdentitySignature).Single().Split('.');
        Assert.True(ForwardedIdentityV2CanonicalInput.TryCreate(request, context, settings.Audience, settings.KeyId, parts[2], parts[3], out var canonical));
        using var key = ECDsa.Create();
        key.ImportPkcs8PrivateKey(Convert.FromBase64String(settings.PrivateKeyPkcs8Base64), out _);
        var signature = Base64UrlEncoder.DecodeBytes(parts[4]);
        Assert.True(key.VerifyData(canonical, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        foreach (var name in new[] { "x-cratis-forwarded-token-sha256", "x-cratis-credential-id", "x-cratis-subject" })
        {
            var original = request.Headers.GetValues(name).Single();
            request.Headers.Remove(name);
            request.Headers.TryAddWithoutValidation(name, "tampered");
            var headers = request.Headers.Select(header => new KeyValuePair<string, IEnumerable<string>>(header.Key, header.Value));
            Assert.True(ForwardedIdentityV2CanonicalInput.TryCreate(request.Method.Method, request.RequestUri!.PathAndQuery, headers, settings.Audience, settings.KeyId, parts[2], parts[3], context.TenantHeader, out var altered));
            Assert.False(key.VerifyData(altered, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
            request.Headers.Remove(name);
            request.Headers.TryAddWithoutValidation(name, original);
        }
    }

    [Theory]
    [InlineData("absent")]
    [InlineData("swapped")]
    [InlineData("duplicate")]
    [InlineData("expired")]
    [InlineData("no-deadline")]
    [InlineData("delegation")]
    [InlineData("wrong-verifier")]
    [InlineData("pat")]
    [InlineData("sender-bound")]
    [InlineData("machine-principal")]
    [InlineData("on-behalf-session")]
    public void should_refuse_incomplete_or_hostile_evidence_without_any_proof(string scenario)
    {
        using var fixture = V2Vector.Load();
        var input = fixture.RootElement.GetProperty("cases")[0].GetProperty("inputs");
        using var request = V2Vector.Request(input);
        var context = Context(input);
        if (scenario != "absent") request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + (scenario == "swapped" ? "different-token" : Token));
        if (scenario == "duplicate") request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + Token);
        context = scenario switch
        {
            "expired" => context with { SnapshotExpiresUtc = DateTimeOffset.UtcNow.AddSeconds(-1) },
            "no-deadline" => context with { SnapshotExpiresUtc = null },
            "delegation" => context with { GrantId = "delegated" },
            "wrong-verifier" => context with { Bearer = context.Bearer! with { Verifier = "pat-verifier" } },
            "pat" => context with { CredentialKind = "pat" },
            "sender-bound" => context with { SenderBinding = "bound" },
            "machine-principal" => context with { CredentialKind = "machine-principal" },
            "on-behalf-session" => context with { CredentialKind = "on-behalf-session" },
            _ => context
        };
        request.Options.Set(ForwardedIdentityTrustedContext.OptionsKey, context);
        request.Headers.TryAddWithoutValidation(Headers.ForwardedIdentitySignature, "v1.stale");
        using var signer = when_signing_with_explicit_trusted_context.Signer(when_signing_with_explicit_trusted_context.Settings());
        Assert.Equal(ForwardedIdentitySigningOutcome.Refused, signer.Sign(request, when_signing_with_explicit_trusted_context.Target()));
        Assert.False(request.Headers.Contains(Headers.ForwardedIdentitySignature));
    }

    static ForwardedIdentityTrustedContext Context(System.Text.Json.JsonElement input)
    {
        var context = V2Vector.Context(input);
        return context with
        {
            CredentialKind = "oauth-grant",
            CredentialId = "grant-record",
            SenderBinding = "none",
            Actor = null,
            GrantId = null,
            Bearer = new(Token, "oauth-verifier", context.Person!.Issuer, context.Person.Subject),
            SnapshotExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(1)
        };
    }
}
