// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes.Dpop;
using Microsoft.AspNetCore.Http.Features;

namespace Cratis.AuthProxy.BearerRoutes.for_DpopProofVerifier;

public class when_mapping_exact_target_paths : given_a_dpop_gate
{
    [Theory]
    [InlineData("/oauth", "https://api.example.test/mcp")]
    [InlineData("/oauth/", "https://api.example.test/mcp/")]
    [InlineData("/oauth/action", "https://api.example.test/mcp/action")]
    [InlineData("/OAUTH/action", null)]
    [InlineData("/oAuth/action", null)]
    [InlineData("/oauthx", null)]
    [InlineData("/oauthx/action", null)]
    public void should_only_substitute_an_exact_mount_boundary(string path, string? target)
    {
        var context = Request();
        context.Request.Path = path;
        DpopTargetUri.TryBuild(context.Request, Policy, out var actual).ShouldEqual(target is not null);
        if (target is not null) actual.ShouldEqual(target);
    }

    [Theory]
    [InlineData("/oauth", "/oauth?query=ignored", "https://api.example.test/mcp")]
    [InlineData("/oauth/", "/oauth/", "https://api.example.test/mcp/")]
    [InlineData("/oauth/a%2Fb", "/oauth/a%2Fb", "https://api.example.test/mcp/a%2Fb")]
    [InlineData("/oauth/a%2fb", "/oauth/a%2fb", "https://api.example.test/mcp/a%2fb")]
    [InlineData("/oauth/a", "/oauth/../a", null)]
    [InlineData("/oauth/a", "/oauth/%2e%2e/a", null)]
    [InlineData("/oauth/a", "/oauth//a", null)]
    [InlineData("/oauth/a", "/oauth/a%", null)]
    [InlineData("/oauth/a", "/oauth/a%GG", null)]
    [InlineData("/oauth/a", "/oauth/a%5C", null)]
    [InlineData("/oauth/a", "/oauth/a%1F", null)]
    public void should_build_from_the_trusted_origin_and_exact_escaped_path(string path, string rawTarget, string? target)
    {
        var context = Request();
        context.Request.Path = path;
        context.Request.Host = new("attacker.example.test");
        context.Request.Headers["Forwarded"] = "host=attacker.example.test;proto=http";
        context.Request.Headers["X-Forwarded-Host"] = "attacker.example.test";
        context.Features.Get<IHttpRequestFeature>()!.RawTarget = rawTarget;
        DpopTargetUri.TryBuild(context.Request, Policy, out var actual).ShouldEqual(target is not null);
        if (target is not null) actual.ShouldEqual(target);
    }

    [Fact]
    public void should_include_path_base_without_an_explicit_mount_mapping()
    {
        var context = Request();
        Policy.Dpop!.PublicPathPrefix = null;
        context.Request.PathBase = "/gateway";
        context.Request.Path = "/oauth/a%2Fb";
        DpopTargetUri.TryBuild(context.Request, Policy, out var target).ShouldBeTrue();
        target.ShouldEqual("https://api.example.test/gateway/oauth/a%2Fb");
        DpopTargetUri.Matches("https://api.example.test/gateway/oauth/a%2fb", target).ShouldBeFalse();
        DpopTargetUri.Matches(target + "?query=ignored", target).ShouldBeFalse();
        DpopTargetUri.Matches(target + "#fragment", target).ShouldBeFalse();
    }

    [Theory]
    [InlineData("/OAUTH")]
    [InlineData("/OAUTH/action")]
    public async Task should_not_forward_a_captured_proof_on_a_case_variant(string path)
    {
        var context = Request();
        context.Request.Path = path;
        await Gate.InvokeAsync(context);
        Refused(context, 401);
        Store.HealthChecks.ShouldEqual(0);
        Store.Consumes.ShouldEqual(0);
    }
}
