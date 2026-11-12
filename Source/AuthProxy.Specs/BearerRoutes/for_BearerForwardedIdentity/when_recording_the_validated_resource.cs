// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerForwardedIdentity;

public class when_recording_the_validated_resource : Specification
{
    [Theory]
    [InlineData("https://api.example.test", "https://api.example.test/", "https://api.example.test/")]
    [InlineData("https://api.example.test/", "https://api.example.test", "https://api.example.test")]
    [InlineData("resource-z", "resource-a", "resource-a")]
    public void should_forward_exactly_one_matching_resource_before_any_claim_mapping(string first, string second, string tokenAudience)
    {
        var route = Route([first, second]);
        route.Route.ClaimMappings = new Dictionary<string, string> { ["aud"] = "mapped_audience" };
        var validation = Validate(route,
            new Claim("aud", tokenAudience),
            new Claim("mapped_audience", "unrelated-resource"),
            new Claim(BearerRouteClaims.Resource, "injected-resource"));

        var principal = BearerForwardedIdentity.From(validation, route).Principal;

        principal.Claims.Single(claim => claim.Type == BearerRouteClaims.Resource).Value.ShouldEqual(tokenAudience);
        principal.Claims.Single(claim => claim.Type == "aud").Value.ShouldEqual("unrelated-resource");
    }

    [Theory]
    [InlineData("resource-z", "resource-a")]
    [InlineData("resource-a", "resource-z")]
    public void should_choose_the_ordinal_first_exact_match_for_multiple_audiences(string first, string second)
    {
        var route = Route([first, second]);
        var validation = Validate(route, new Claim("aud", "resource-z"), new Claim("aud", "resource-a"));

        var identity = BearerForwardedIdentity.From(validation, route);

        identity.Principal.Claims.Single(claim => claim.Type == BearerRouteClaims.Resource).Value.ShouldEqual("resource-a");
    }

    static BearerTokenValidation Validate(ResolvedBearerRoute route, params Claim[] claims) =>
        BearerTokenValidator.ValidateClaims(route, route.Issuers.Single(), [new Claim("sub", "account"), new Claim("tid", "tenant"), .. claims]);

    static ResolvedBearerRoute Route(string[] audiences)
    {
        var config = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["app"] = new()
                {
                    Backend = new() { BaseUrl = "https://backend.example.test" },
                    BearerRoutes = [new() { PathPrefix = "/api", Issuers = [new() { Issuer = "https://issuer.example.test" }], Audiences = audiences }],
                },
            },
        };
        return BearerRouteTable.All(config).Single();
    }
}
