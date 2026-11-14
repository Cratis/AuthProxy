// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes;
using Cratis.AuthProxy.BearerRoutes.Introspection;
using Cratis.AuthProxy.ForwardedIdentity;
using Cratis.AuthProxy.Security.for_V2.given;
using Cratis.Specifications;
using Microsoft.AspNetCore.Http;
using NSubstitute;
using Yarp.ReverseProxy.Transforms;

namespace Cratis.AuthProxy.Security.for_V2;

public class when_producing_oauth_grant_evidence : Specification
{
    [Fact]
    public async Task should_transport_only_verified_evidence_after_scrubbing_caller_headers()
    {
        using var gate = new OAuthGrantGate();
        var token = gate.Mint();
        await gate.Invoke(token);
        var identity = Assert.IsType<BearerForwardedIdentity>(gate.Forwarded);
        var trusted = Assert.IsType<ForwardedIdentityTrustedContext>(identity.TrustedContext);
        Assert.Equal("oauth-grant", trusted.CredentialKind);
        Assert.Equal(OAuthGrantGate.CredentialId, trusted.CredentialId);
        Assert.Equal("7", trusted.PolicyEpoch);
        Assert.Equal("none", trusted.SenderBinding);
        Assert.Equal(OAuthGrantGate.Realm, trusted.Person!.Issuer);
        Assert.Equal(OAuthGrantGate.Subject, trusted.Person.Subject);
        Assert.Equal(token, trusted.Bearer!.Token);
        Assert.Null(trusted.Actor);
        Assert.Null(trusted.GrantId);
        using var outbound = new HttpRequestMessage(HttpMethod.Get, "https://backend.example.test/api/resource");
        outbound.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
        outbound.Headers.TryAddWithoutValidation("x-cratis-credential-id", "caller-value");
        outbound.Headers.TryAddWithoutValidation("x-cratis-act", "caller-actor");
        outbound.Headers.TryAddWithoutValidation(Headers.ForwardedIdentitySignature, "v1.caller-proof");
        gate.Http.Items[BearerRouteDefaults.ForwardedIdentityItemKey] = identity;
        await new BearerRouteHeadersTransform().ApplyAsync(new RequestTransformContext { HttpContext = gate.Http, ProxyRequest = outbound });
        Assert.True(outbound.Options.TryGetValue(ForwardedIdentityTrustedContext.OptionsKey, out var transported));
        Assert.Same(trusted, transported);
        Assert.False(outbound.Headers.Contains("x-cratis-credential-id"));
        Assert.False(outbound.Headers.Contains("x-cratis-act"));
        Assert.False(outbound.Headers.Contains(Headers.ForwardedIdentitySignature));
        Assert.NotNull(outbound.Headers.Authorization);
    }

    [Theory]
    [InlineData("idp")]
    [InlineData("auth_time")]
    [InlineData("acr")]
    public async Task should_deny_missing_or_empty_required_authentication_evidence(string claim)
    {
        using var missing = new OAuthGrantGate();
        await missing.Invoke(missing.Mint(claims => claims.Remove(claim)));
        Assert.Null(missing.Forwarded);
        Assert.Equal(StatusCodes.Status401Unauthorized, missing.Http.Response.StatusCode);
        using var empty = new OAuthGrantGate();
        await empty.Invoke(empty.Mint(claims => claims[claim] = string.Empty));
        Assert.Null(empty.Forwarded);
    }

    [Theory]
    [InlineData("email-subject")]
    [InlineData("machine-subject")]
    [InlineData("upper-case-subject")]
    [InlineData("unreviewed-acr")]
    [InlineData("object-amr")]
    [InlineData("bad-auth-time")]
    [InlineData("actor")]
    [InlineData("delegated-grant")]
    [InlineData("cid-mismatch")]
    [InlineData("sender-constrained")]
    public async Task should_deny_unreviewed_or_delegated_person_evidence(string scenario)
    {
        using var gate = new OAuthGrantGate();
        var token = gate.Mint(claims =>
        {
            switch (scenario)
            {
                case "email-subject": claims["sub"] = "person@example.test"; break;
                case "machine-subject": claims["sub"] = "service-account-1"; break;
                case "upper-case-subject": claims["sub"] = "ABCDEFAB-1111-4111-8111-111111111111"; break;
                case "unreviewed-acr": claims["acr"] = "super-admin"; break;
                case "object-amr": claims["amr"] = new Dictionary<string, string> { ["method"] = "pwd" }; break;
                case "bad-auth-time": claims["auth_time"] = "123"; break;
                case "actor": claims["act"] = new Dictionary<string, string> { ["sub"] = "actor" }; break;
                case "delegated-grant": claims["grant_id"] = "delegated"; break;
                case "cid-mismatch": claims["cid"] = "33333333-3333-4333-8333-333333333333"; break;
                case "sender-constrained": claims["cnf"] = new Dictionary<string, string> { ["jkt"] = "bound-key" }; break;
            }
        });
        await gate.Invoke(token);
        Assert.Null(gate.Forwarded);
        Assert.Equal(StatusCodes.Status401Unauthorized, gate.Http.Response.StatusCode);
    }

    [Theory]
    [InlineData(IntrospectionVerdict.Inactive, "credential", false)]
    [InlineData(IntrospectionVerdict.Unavailable, "credential", false)]
    [InlineData(IntrospectionVerdict.Unavailable, "credential", true)]
    [InlineData(IntrospectionVerdict.Active, null, false)]
    [InlineData(IntrospectionVerdict.Active, null, true)]
    public async Task should_not_forward_without_active_authoritative_grant_evidence(IntrospectionVerdict verdict, string? credentialId, bool failOpen)
    {
        using var gate = new OAuthGrantGate();
        gate.Route.IntrospectionUnavailable = failOpen ? C.IntrospectionFailurePolicy.Accept : C.IntrospectionFailurePolicy.Refuse;
        gate.Introspector.IntrospectWithEvidence(Arg.Any<string>(), Arg.Any<BearerTokenValidation>(), Arg.Any<ResolvedBearerIssuer>(), Arg.Any<CancellationToken>()).Returns(new IntrospectionResult(verdict, credentialId is null ? null : new(credentialId, null)) { ValidUntil = DateTimeOffset.UtcNow.AddSeconds(30) });
        await gate.Invoke(gate.Mint());
        Assert.Null(gate.Forwarded);
    }

    [Fact]
    public async Task should_deny_expired_introspection_evidence_and_unforwarded_authorization()
    {
        using var gate = new OAuthGrantGate();
        gate.Introspector.IntrospectWithEvidence(Arg.Any<string>(), Arg.Any<BearerTokenValidation>(), Arg.Any<ResolvedBearerIssuer>(), Arg.Any<CancellationToken>()).Returns(new IntrospectionResult(IntrospectionVerdict.Active, new(OAuthGrantGate.CredentialId, null), DateTimeOffset.UtcNow.AddSeconds(-1)) { ValidUntil = DateTimeOffset.UtcNow.AddSeconds(30) });
        await gate.Invoke(gate.Mint());
        Assert.Null(gate.Forwarded);
        using var unforwarded = new OAuthGrantGate();
        unforwarded.Route.ForwardAuthorizationHeader = false;
        await unforwarded.Invoke(unforwarded.Mint());
        Assert.Null(unforwarded.Forwarded);
    }

    [Fact]
    public async Task should_accept_an_absent_cid_but_not_an_authoritative_id_from_the_jwt_alone()
    {
        using var gate = new OAuthGrantGate();
        await gate.Invoke(gate.Mint(claims => claims.Remove("cid")));
        Assert.NotNull(gate.Forwarded?.TrustedContext);
    }

    [Theory]
    [InlineData("issuer")]
    [InlineData("audience")]
    [InlineData("expired")]
    [InlineData("tampered")]
    public async Task should_never_introspect_or_forward_a_locally_invalid_token(string scenario)
    {
        using var gate = new OAuthGrantGate();
        var token = gate.Mint(configure: descriptor =>
        {
            if (scenario == "issuer") descriptor.Issuer = "https://untrusted.example.test";
            if (scenario == "audience") descriptor.Audience = "another-backend";
            if (scenario == "expired")
            {
                descriptor.IssuedAt = DateTime.UtcNow.AddMinutes(-10);
                descriptor.NotBefore = DateTime.UtcNow.AddMinutes(-10);
                descriptor.Expires = DateTime.UtcNow.AddMinutes(-5);
            }
        });
        if (scenario == "tampered")
        {
            var start = token.LastIndexOf('.') + 1;
            token = token[..start] + (token[start] == 'A' ? 'B' : 'A') + token[(start + 1)..];
        }
        await gate.Invoke(token);
        Assert.Null(gate.Forwarded);
        Assert.Equal(StatusCodes.Status401Unauthorized, gate.Http.Response.StatusCode);
        await gate.Introspector.DidNotReceive().IntrospectWithEvidence(Arg.Any<string>(), Arg.Any<BearerTokenValidation>(), Arg.Any<ResolvedBearerIssuer>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task should_not_make_v1_routes_depend_on_new_grant_evidence()
    {
        using var gate = new OAuthGrantGate();
        gate.Service.ForwardedIdentity!.Version = "v1";
        gate.Introspector.Introspect(Arg.Any<string>(), Arg.Any<BearerTokenValidation>(), Arg.Any<ResolvedBearerIssuer>(), Arg.Any<CancellationToken>()).Returns(IntrospectionVerdict.Active);
        await gate.Invoke(gate.Mint(claims => claims.Remove("idp")));
        Assert.NotNull(gate.Forwarded);
        Assert.Null(gate.Forwarded.TrustedContext);
    }
}
