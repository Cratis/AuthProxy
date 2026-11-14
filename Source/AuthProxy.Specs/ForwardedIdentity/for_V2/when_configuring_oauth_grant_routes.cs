// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes;

namespace Cratis.AuthProxy.ForwardedIdentity.for_V2;

public class when_configuring_oauth_grant_routes : Specification
{
    [Theory]
    [InlineData("v2", false, true, "ForwardAuthorizationHeader")]
    [InlineData("v2", true, false, "requires introspection")]
    [InlineData("v1", false, false, null)]
    public void should_require_authorization_and_introspection_only_for_v2(string version, bool forward, bool introspection, string? expected)
    {
        var route = new C.BearerRoute
        {
            PathPrefix = "/api",
            Audiences = ["backend"],
            ForwardAuthorizationHeader = forward,
            Issuers = [new() { Issuer = "https://realm.example", Introspection = introspection ? new() { Endpoint = "https://realm.example/introspect", ClientId = "client", ClientSecret = "synthetic-test-only" } : null }]
        };
        var settings = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["app"] = new() { Backend = new() { BaseUrl = "https://backend.example" }, BearerRoutes = [route], ForwardedIdentity = new() { Version = version } }
            }
        };
        var result = new BearerRouteConfigurationValidator().Validate(null, settings);
        var failures = result.Failures ?? [];
        if (expected is not null) Assert.Contains(failures, failure => failure.Contains(expected, StringComparison.Ordinal));
        else Assert.DoesNotContain(failures, failure => failure.Contains("v2 OAuth grant", StringComparison.Ordinal));
    }

    [Fact]
    public void should_refuse_dpop_for_v2_oauth_but_not_require_oauth_evidence_on_pat_only_routes()
    {
        var route = new C.BearerRoute { PathPrefix = "/api", Dpop = new() { PublicOrigin = "https://public.example.test" }, Issuers = [new() { Issuer = "https://realm.example.test" }] };
        var config = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["app"] = new() { Backend = new() { BaseUrl = "https://backend.example.test" }, BearerRoutes = [route], ForwardedIdentity = new() { Version = "v2" } }
            }
        };
        var validator = new BearerRouteConfigurationValidator();
        Assert.Contains(validator.Validate(null, config).Failures!, failure => failure.Contains("Dpop is not supported for v2", StringComparison.Ordinal));
        route.Dpop = null;
        route.Issuers.Clear();
        route.PersonalAccessTokens = new() { ResourceKey = "backend" };
        Assert.DoesNotContain(validator.Validate(null, config).Failures ?? [], failure => failure.Contains("v2 OAuth grant", StringComparison.Ordinal));
    }
}
