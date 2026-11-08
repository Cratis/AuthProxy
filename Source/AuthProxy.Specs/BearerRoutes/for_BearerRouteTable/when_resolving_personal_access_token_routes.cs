// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteTable;

public class when_resolving_personal_access_token_routes : Specification
{
    static C.AuthProxy Configure(params C.BearerRoute[] routes) => new()
    {
        Services = new Dictionary<string, C.Service>
        {
            ["api"] = new() { Backend = new() { BaseUrl = "https://backend.example.test" }, IdentityVerification = C.IdentityVerificationMode.BestEffort, BearerRoutes = [.. routes] },
        },
    };

    static C.BearerRoute Route(string prefix, string? resourceKey, bool issuer, string? metadataUrl = null) => new()
    {
        PathPrefix = prefix,
        Issuers = issuer ? [new() { Issuer = "https://issuer.example.test" }] : [],
        Audiences = issuer ? ["direct-api"] : [],
        PersonalAccessTokens = resourceKey is null ? null : new() { ResourceKey = resourceKey },
        ResourceMetadataUrl = metadataUrl ?? string.Empty,
    };

    [Fact]
    public void should_resolve_a_route_with_only_tokens_as_pat_only_on_its_resource()
    {
        var resolved = BearerRouteTable.All(Configure(Route("/pat", "studio", issuer: false))).Single();
        resolved.Profile.ShouldEqual(BearerProfile.PatOnly);
        resolved.ResourceKey.ShouldEqual("studio");
        resolved.ResourceMetadataPath.ShouldEqual("/.well-known/oauth-protected-resource/pat");
    }

    [Fact]
    public void should_resolve_a_route_with_both_as_combined()
    {
        var resolved = BearerRouteTable.All(Configure(Route("/both", "direct", issuer: true, "https://direct.example.test/.well-known/oauth-protected-resource/both"))).Single();
        resolved.Profile.ShouldEqual(BearerProfile.Combined);
        resolved.ResourceKey.ShouldEqual("direct");
        resolved.ResourceMetadataPath.ShouldEqual("/.well-known/oauth-protected-resource/both");
    }

    [Fact]
    public void should_resolve_a_route_with_only_issuers_as_oauth_only()
    {
        var resolved = BearerRouteTable.All(Configure(Route("/oauth", null, issuer: true))).Single();
        resolved.Profile.ShouldEqual(BearerProfile.OAuthOnly);
        resolved.ResourceKey.ShouldBeNull();
    }

    [Fact]
    public void should_not_resolve_an_unregistered_resource_key() =>
        BearerRouteTable.All(Configure(Route("/pat", "Direct", issuer: false))).ShouldBeEmpty();

    [Fact]
    public void should_not_resolve_a_route_with_nothing_to_accept() =>
        BearerRouteTable.All(Configure(Route("/none", null, issuer: false))).ShouldBeEmpty();

    [Fact]
    public void should_not_resolve_a_token_only_route_that_names_oauth_metadata() =>
        BearerRouteTable.All(Configure(Route("/pat", "direct", issuer: false, "https://direct.example.test/.well-known/oauth-protected-resource/pat"))).ShouldBeEmpty();

    [Theory]
    [InlineData("direct", false)]
    [InlineData("stage-app", false)]
    [InlineData("Direct", true)]
    [InlineData("", true)]
    [InlineData("stage-", true)]
    public void should_refuse_an_unregistered_resource_key_at_startup(string resourceKey, bool refused)
    {
        var result = new BearerRouteConfigurationValidator().Validate(null, Configure(Route("/pat", resourceKey, issuer: false)));
        result.Failed.ShouldEqual(refused);
    }

    [Fact]
    public void should_refuse_a_token_only_route_that_names_oauth_metadata_at_startup() =>
        new BearerRouteConfigurationValidator().Validate(null, Configure(Route("/pat", "direct", issuer: false, "https://direct.example.test/.well-known/oauth-protected-resource/pat"))).Failed.ShouldBeTrue();
}
