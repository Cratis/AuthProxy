// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.ForwardedIdentity.for_V2;

public class when_forwarding_browser_sessions : Specification
{
    [Fact]
    public void should_sign_the_selected_cookie_and_replace_a_spoofed_custom_tenant()
    {
        using var fixture = new BrowserSessionFixture();
        using var request = fixture.Request();
        request.Headers.Add(fixture.Settings.TenantHeader, "attacker");
        Assert.Equal(ForwardedIdentitySigningOutcome.SignatureCreated, fixture.Signer.Sign(request, when_signing_with_explicit_trusted_context.Target()));
        Assert.Equal("browser-session", request.Headers.GetValues("x-cratis-credential-kind").Single());
        Assert.Equal("1700000000", request.Headers.GetValues("x-cratis-auth-time").Single());
        Assert.Equal("tenant-one", request.Headers.GetValues(fixture.Settings.TenantHeader).Single());
        Assert.Equal("none", request.Headers.GetValues("x-cratis-sender-binding").Single());
    }

    [Fact]
    public void should_preserve_the_credential_and_verified_authentication_time_across_cookie_protection_and_renewal()
    {
        using var fixture = new BrowserSessionFixture();
        var before = BrowserSessionEvidence.For(fixture.Context);
        Assert.NotNull(before);
        var protector = new TicketDataFormat(new Microsoft.AspNetCore.DataProtection.EphemeralDataProtectionProvider().CreateProtector("browser-spec"));
        var ticket = protector.Unprotect(protector.Protect(new AuthenticationTicket(fixture.Principal, fixture.Properties, CookieAuthenticationDefaults.AuthenticationScheme)))!;
        ticket.Properties.IssuedUtc = DateTimeOffset.UtcNow;
        ticket.Properties.ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1);
        fixture.Context.User = ticket.Principal;
        fixture.Context.Features.Set<IAuthenticateResultFeature>(new ResultFeature(AuthenticateResult.Success(ticket)));
        var after = BrowserSessionEvidence.For(fixture.Context);
        Assert.Equal(before.CredentialId, after!.CredentialId);
        Assert.Equal(before.Person, after.Person);
        Assert.Equal("1700000000", after.Person!.AuthenticationTime);
    }

    [Fact]
    public void should_assign_a_different_credential_to_each_sign_in_even_with_the_same_subject_and_jti()
    {
        using var fixture = new BrowserSessionFixture();
        var first = BrowserSessionEvidence.For(fixture.Context)!.CredentialId;
        fixture.Stamp();
        Assert.NotEqual(first, BrowserSessionEvidence.For(fixture.Context)!.CredentialId);
        Assert.True(Guid.TryParseExact(first, "D", out _));
    }

    [Theory]
    [InlineData("Authorization", "Bearer unsupported")]
    [InlineData("Authorization", "pat_unsupported")]
    [InlineData("DPoP", "unsupported-proof")]
    public void should_refuse_other_inbound_credentials_even_alongside_a_valid_cookie(string header, string value)
    {
        using var fixture = new BrowserSessionFixture();
        fixture.Context.Request.Headers[header] = value;
        using var request = fixture.Request();
        Assert.Equal(ForwardedIdentitySigningOutcome.Refused, fixture.Signer.Sign(request, when_signing_with_explicit_trusted_context.Target()));
        Assert.False(request.Headers.Contains(Headers.ForwardedIdentitySignature));
    }

    [Theory]
    [InlineData("Bearer")]
    [InlineData("Pat")]
    [InlineData("DPoP")]
    public void should_never_reclassify_an_authenticated_non_cookie_ticket(string scheme)
    {
        using var fixture = new BrowserSessionFixture();
        fixture.Authenticate(scheme);
        Assert.Null(BrowserSessionEvidence.For(fixture.Context));
    }

    [Theory]
    [InlineData("legacy")]
    [InlineData("malformed")]
    [InlineData("provider")]
    [InlineData("authority")]
    [InlineData("subject")]
    [InlineData("auth-time")]
    [InlineData("missing-time")]
    public void should_refuse_incomplete_or_mismatched_protected_evidence(string attack)
    {
        using var fixture = new BrowserSessionFixture();
        using var request = fixture.Request();
        switch (attack)
        {
            case "legacy": fixture.Properties.Items.Remove(BrowserSessionEvidence.PropertyKey); break;
            case "malformed": fixture.Properties.Items[BrowserSessionEvidence.PropertyKey] = "{"; break;
            case "provider": fixture.Provider.Type = C.OidcProviderType.Microsoft; break;
            case "authority": fixture.Provider.Authority = "https://other.example/"; break;
            case "subject": ((ClaimsIdentity)fixture.Principal.Identity!).AddClaim(new(CanonicalIdentityClaims.Subject, "another")); break;
            case "auth-time": fixture.Properties.Items[SessionAuthenticationTime.PropertyKey] = "1700000001"; break;
            case "missing-time": fixture.Properties.Items.Remove(SessionAuthenticationTime.PropertyKey); break;
        }
        Assert.Equal(ForwardedIdentitySigningOutcome.Refused, fixture.Signer.Sign(request, when_signing_with_explicit_trusted_context.Target()));
        Assert.False(request.Headers.Contains(Headers.ForwardedIdentitySignature));
    }

    [Theory]
    [InlineData("issuer")]
    [InlineData("subject")]
    [InlineData("time")]
    [InlineData("idp")]
    [InlineData("provider")]
    [InlineData("unverified")]
    public void should_not_mint_evidence_from_mismatched_or_arbitrary_canonical_providers(string attack)
    {
        using var fixture = new BrowserSessionFixture();
        switch (attack)
        {
            case "issuer": fixture.Verified(issuer: "https://other.example/"); break;
            case "subject": fixture.Verified(subject: "another"); break;
            case "time": fixture.Verified(time: 1700000001); break;
            case "idp": fixture.Verified(idp: ""); break;
            case "provider": fixture.Provider.Type = C.OidcProviderType.Microsoft; break;
            case "unverified": fixture.Context.Items.Clear(); break;
        }
        fixture.Stamp();
        Assert.False(fixture.Properties.Items.ContainsKey(BrowserSessionEvidence.PropertyKey));
        Assert.Null(BrowserSessionEvidence.For(fixture.Context));
    }

    [Theory]
    [InlineData("pat")]
    [InlineData("oauth-grant")]
    [InlineData("on-behalf-session")]
    [InlineData("machine-principal")]
    [InlineData("workload")]
    public void should_refuse_non_browser_explicit_context_until_it_has_an_approved_producer(string kind)
    {
        using var fixture = new BrowserSessionFixture();
        using var request = fixture.Request();
        request.Options.Set(ForwardedIdentityTrustedContext.OptionsKey, BrowserSessionEvidence.For(fixture.Context)! with { CredentialKind = kind });
        Assert.Equal(ForwardedIdentitySigningOutcome.Refused, fixture.Signer.Sign(request, when_signing_with_explicit_trusted_context.Target()));
    }

    [Fact]
    public void should_sign_a_queued_browser_snapshot_without_an_ambient_request()
    {
        using var fixture = new BrowserSessionFixture();
        using var request = fixture.Request();
        var snapshot = BrowserSessionEvidence.Read(fixture.Context, fixture.Principal, fixture.Properties)!;
        request.Options.Set(ForwardedIdentityTrustedContext.OptionsKey, snapshot);
        fixture.Accessor.HttpContext = null;
        Assert.Equal(ForwardedIdentitySigningOutcome.SignatureCreated, fixture.Signer.Sign(request, when_signing_with_explicit_trusted_context.Target()));
        Assert.Equal(snapshot.CredentialId, request.Headers.GetValues("x-cratis-credential-id").Single());
    }

    [Fact]
    public void should_never_replace_an_explicitly_missing_callback_snapshot_with_an_ambient_cookie()
    {
        using var fixture = new BrowserSessionFixture();
        using var request = fixture.Request();
        request.Options.Set(ForwardedIdentityTrustedContext.OptionsKey, new(string.Empty, string.Empty, string.Empty));
        Assert.Equal(ForwardedIdentitySigningOutcome.Refused, fixture.Signer.Sign(request, when_signing_with_explicit_trusted_context.Target()));
    }

    sealed class ResultFeature(AuthenticateResult result) : IAuthenticateResultFeature
    {
        public AuthenticateResult? AuthenticateResult { get; set; } = result;
    }
}
