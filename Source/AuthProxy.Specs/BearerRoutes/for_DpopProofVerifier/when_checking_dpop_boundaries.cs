// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using System.Text.Json;
using Cratis.AuthProxy.BearerRoutes.Dpop;
using Cratis.AuthProxy.ForwardedIdentity;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.BearerRoutes.for_DpopProofVerifier;

public class when_checking_dpop_boundaries : given_a_dpop_gate
{
    [Theory]
    [InlineData("{}")]
    [InlineData("null")]
    [InlineData("{\"jkt\":7}")]
    [InlineData("{\"jkt\":\"bad\"}")]
    [InlineData("{\"x5t#S256\":\"certificate\"}")]
    [InlineData("{\"jwk\":{}}")]
    [InlineData("{\"jkt\":\"a\",\"jkt\":\"b\"}")]
    public void should_refuse_unsupported_or_malformed_confirmation(string confirmation)
    {
        BearerTokenValidator.ValidateClaims(Route, Route.Issuers[0], [new("sub", "subject"), new("tid", "tenant-a"), new("cnf", confirmation)]).Succeeded.ShouldBeFalse();
    }

    [Fact]
    public void should_refuse_duplicate_confirmation_claims()
    {
        var cnf = new Claim("cnf", "{\"jkt\":\"" + Jkt + "\"}");
        BearerTokenValidator.ValidateClaims(Route, Route.Issuers[0], [new("sub", "subject"), new("tid", "tenant-a"), cnf, cnf]).Succeeded.ShouldBeFalse();
    }

    [Fact]
    public void should_preserve_unbound_bearer_behavior_and_refuse_unbound_dpop()
    {
        Policy.Dpop = null;
        var unbound = BearerTokenValidator.ValidateClaims(Route, Route.Issuers[0], [new("sub", "subject"), new("tid", "tenant-a")]);
        unbound.Succeeded.ShouldBeTrue();
        DpopPresentation.Check(Request(scheme: "Bearer").Request, Route, unbound).Succeeded.ShouldBeTrue();
        DpopPresentation.Check(Request().Request, Route, unbound).Succeeded.ShouldBeFalse();
    }

    [Fact]
    public void should_require_confirmation_when_the_route_requires_dpop()
    {
        Policy.Dpop!.Mode = C.DpopMode.Require;
        var token = BearerTokenValidator.ValidateClaims(Route, Route.Issuers[0], [new("sub", "subject"), new("tid", "tenant-a")]);
        DpopPresentation.Check(Request(scheme: "Bearer").Request, Route, token).Succeeded.ShouldBeFalse();
    }

    [Fact]
    public void should_not_add_sender_constraints_from_introspection()
    {
        using var root = JsonDocument.Parse("{\"cnf\":{\"jkt\":\"" + Jkt + "\"}}");
        DpopIntrospection.Contradiction(root.RootElement, Validation with { SenderConstraint = null }).ShouldEqual("cnf");
        DpopIntrospection.Contradiction(root.RootElement, Validation).ShouldBeNull();
    }

    [Theory]
    [InlineData("{\"token_type\":\"Bearer\"}")]
    [InlineData("{\"cnf\":{\"jkt\":\"wrong\"}}")]
    [InlineData("{\"cnf\":null}")]
    public void should_refuse_contradictory_introspection(string json)
    {
        using var root = JsonDocument.Parse(json);
        DpopIntrospection.Contradiction(root.RootElement, Validation).ShouldNotBeNull();
    }

    [Fact]
    public void should_accept_matching_optional_introspection_evidence()
    {
        using var root = JsonDocument.Parse("{\"cnf\":{\"jkt\":\"" + Jkt + "\"},\"token_type\":\"DPoP\"}");
        DpopIntrospection.Contradiction(root.RootElement, Validation).ShouldBeNull();
        Policy.IntrospectionUnavailable = C.IntrospectionFailurePolicy.Accept;
        DpopIntrospection.AllowsUnavailable(Route).ShouldBeFalse();
    }

    [Theory]
    [InlineData("https://api.example.test/mcp?x=1")]
    [InlineData("https://api.example.test/mcp#fragment")]
    [InlineData("https://api.example.test/mcp/../mcp")]
    [InlineData("https://api.example.test/%2e%2e/mcp")]
    [InlineData("https://api.example.test//mcp")]
    [InlineData("https://person@api.example.test/mcp")]
    [InlineData("http://api.example.test/mcp")]
    [InlineData("https://api.example.test/MCP")]
    [InlineData("https://api.example.test/mcp/")]
    public void should_refuse_target_aliases(string target) => DpopTargetUri.Matches(target, Target).ShouldBeFalse();

    [Fact]
    public void should_never_normalize_a_different_escaped_target_into_a_match()
    {
        DpopTargetUri.Matches("HTTPS://API.EXAMPLE.TEST:443/%6dcp", Target).ShouldBeFalse();
        DpopTargetUri.Matches(Target + "/a%2fb", Target + "/a%2Fb").ShouldBeFalse();
        DpopTargetUri.Matches(Target + "/a%2Fb", Target + "/a/b").ShouldBeFalse();
    }

    [Fact]
    public void should_preserve_existing_standard_base64_sender_values()
    {
        var previous = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"jkt\":\"" + Jkt + "\",\"jti\":\"existing-id\"}"));
        var context = new ForwardedIdentityTrustedContext("machine-principal", "synthetic-credential", previous);
        ForwardedIdentityV2ContextHeaders.TryHeaders(context, out var headers).ShouldBeTrue();
        headers["x-cratis-sender-binding"].ShouldEqual(previous);
        DpopEnforcement.SenderBinding(Jkt, "existing-id").ShouldEqual(previous);
    }

    [Fact]
    public void should_bind_nonce_to_route_key_and_lifetime()
    {
        var nonce = new DpopNonce(Protection, Clock);
        var value = nonce.Create(Route, Jkt);
        nonce.Valid(value, Route, Jkt).ShouldBeTrue();
        nonce.Valid(value, Route, new string('A', 43)).ShouldBeFalse();
        new DpopNonce(new EphemeralDataProtectionProvider(), Clock).Valid(value, Route, Jkt).ShouldBeFalse();
        Policy.Dpop!.PublicOrigin = "https://other.example.test";
        nonce.Valid(value, Route, Jkt).ShouldBeFalse();
        Policy.Dpop.PublicOrigin = "https://api.example.test";
        Clock.Seconds += 330;
        nonce.Valid(value, Route, Jkt).ShouldBeFalse();
    }

    [Fact]
    public void should_validate_replay_and_route_configuration_without_printing_secrets()
    {
        var failures = new List<string>();
        DpopConfiguration.Validate(Policy, Options, "route", failures);
        failures.Count.ShouldEqual(1);
        Options.Dpop.ReplayStore.Redis = new() { ConnectionString = "replay.example.test:6379", KeyPrefix = "synthetic-deployment" };
        failures.Clear();
        DpopConfiguration.Validate(Policy, Options, "route", failures);
        failures.ShouldBeEmpty();
        Policy.ForwardAuthorizationHeader = true;
        Policy.PersonalAccessTokens = new() { ResourceKey = "direct" };
        Policy.IntrospectionUnavailable = C.IntrospectionFailurePolicy.Accept;
        Policy.Dpop!.PublicOrigin = "http://api.example.test";
        Policy.Dpop.PublicPathPrefix = "/mcp/../other";
        DpopConfiguration.Validate(Policy, Options, "route", failures);
        failures.Count.ShouldEqual(5);
    }
}
