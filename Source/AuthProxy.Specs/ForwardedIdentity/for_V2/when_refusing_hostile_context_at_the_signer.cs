// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;

namespace Cratis.AuthProxy.ForwardedIdentity.for_V2;

public class when_refusing_hostile_context_at_the_signer : Specification
{
    [Theory]
    [InlineData("pat-kind")]
    [InlineData("account-key")]
    [InlineData("service-bearer")]
    [InlineData("missing-grant")]
    [InlineData("duplicate-authorization")]
    public void should_refuse_hostile_evidence_without_leaving_a_proof(string scenario)
    {
        using var fixture = V2Vector.Load();
        var input = fixture.RootElement.GetProperty("cases")[0].GetProperty("inputs");
        using var request = V2Vector.Request(input);
        var context = V2Vector.Context(input);
        var person = context.Person!;
        const string Token = "fixture_pat_test-only";
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + Token);
        context = context with { Bearer = new(Token, "pat-verifier", person.Issuer, person.Subject) };
        context = scenario switch
        {
            "pat-kind" => context with { CredentialKind = "oauth-grant" },
            "account-key" => context with { CredentialKind = "pat", Bearer = context.Bearer! with { Subject = "11111111-1111-4111-8111-111111111111" } },
            "service-bearer" => context with { CredentialKind = "machine-principal", Person = null },
            "missing-grant" => context with { CredentialKind = "on-behalf-session", Actor = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"iss\":\"https://realm.example\",\"sub\":\"actor\"}")), GrantId = null },
            _ => context with { CredentialKind = "pat" }
        };
        if (scenario == "missing-grant")
        {
            request.Headers.Remove("Authorization");
            context = context with { Bearer = null };
        }
        if (scenario == "duplicate-authorization") Assert.True(request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + Token));
        request.Options.Set(ForwardedIdentityTrustedContext.OptionsKey, context);
        request.Headers.Add(Headers.ForwardedIdentitySignature, "v1.stale-proof");
        using var signer = when_signing_with_explicit_trusted_context.Signer(when_signing_with_explicit_trusted_context.Settings());
        Assert.Equal(ForwardedIdentitySigningOutcome.Refused, signer.Sign(request, when_signing_with_explicit_trusted_context.Target()));
        Assert.False(request.Headers.Contains(Headers.ForwardedIdentitySignature));
    }

    [Theory]
    [InlineData("")]
    [InlineData("BASIC")]
    [InlineData("mfa")]
    [InlineData("unreviewed-strength")]
    public void should_refuse_unreviewed_authentication_strength(string acr)
    {
        using var fixture = V2Vector.Load();
        var input = fixture.RootElement.GetProperty("cases")[0].GetProperty("inputs");
        using var request = V2Vector.Request(input);
        var context = V2Vector.Context(input);
        request.Options.Set(ForwardedIdentityTrustedContext.OptionsKey, context with { Person = context.Person! with { AuthenticationContext = acr } });
        using var signer = when_signing_with_explicit_trusted_context.Signer(when_signing_with_explicit_trusted_context.Settings());
        Assert.Equal(ForwardedIdentitySigningOutcome.Refused, signer.Sign(request, when_signing_with_explicit_trusted_context.Target()));
        Assert.False(request.Headers.Contains(Headers.ForwardedIdentitySignature));
    }

    [Theory]
    [InlineData("name-count")]
    [InlineData("single-value")]
    [InlineData("total-bytes")]
    [InlineData("header-name")]
    public void should_bound_the_snapshot_before_decoding_the_principal(string limit)
    {
        using var fixture = V2Vector.Load();
        var input = fixture.RootElement.GetProperty("cases")[0].GetProperty("inputs");
        using var request = V2Vector.Request(input);
        var context = V2Vector.Context(input);
        request.Options.Set(ForwardedIdentityTrustedContext.OptionsKey, context);
        request.Headers.Remove(Headers.Principal);
        request.Headers.TryAddWithoutValidation(Headers.Principal, limit == "single-value" ? new string('A', 32769) : "not-json");
        if (limit == "header-name") request.Headers.TryAddWithoutValidation(Headers.PrincipalPrefix + new string('a', 32769), "value");
        var count = limit == "name-count" ? 65 : limit == "total-bytes" ? 50 : 0;
        for (var index = 0; index < count; index++) request.Headers.TryAddWithoutValidation(Headers.PrincipalPrefix + index, new string('a', limit == "total-bytes" ? 700 : 1));
        Assert.False(ForwardedIdentityV2CanonicalInput.HasBoundedSnapshot(request, context.TenantHeader));
        using var signer = when_signing_with_explicit_trusted_context.Signer(when_signing_with_explicit_trusted_context.Settings());
        Assert.Equal(ForwardedIdentitySigningOutcome.Refused, signer.Sign(request, when_signing_with_explicit_trusted_context.Target()));
        Assert.False(request.Headers.Contains(Headers.ForwardedIdentitySignature));
    }
}
