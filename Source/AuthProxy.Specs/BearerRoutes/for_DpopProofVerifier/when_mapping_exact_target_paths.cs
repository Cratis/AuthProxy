// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes.Dpop;

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
