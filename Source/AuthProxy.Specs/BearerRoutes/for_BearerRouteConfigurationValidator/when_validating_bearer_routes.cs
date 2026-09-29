// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteConfigurationValidator;

/// <summary>
/// A bearer route AuthProxy cannot enforce as written is left on the browser-session model, which is closed but
/// invisible: the operator believes an API is served and every client is sent to sign in. Each such mistake is
/// refused at startup instead, and a deployment without bearer routes is not affected at all.
/// </summary>
public class when_validating_bearer_routes : Specification
{
    ValidateOptionsResult _valid;
    ValidateOptionsResult _withoutRoutes;
    ValidateOptionsResult _withoutAudience;
    ValidateOptionsResult _withPlainHttpIssuer;
    ValidateOptionsResult _overlappingAnonymousPath;
    ValidateOptionsResult _withoutBackend;
    ValidateOptionsResult _withLargeClockSkew;
    ValidateOptionsResult _mappingIntoReservedClaim;
    ValidateOptionsResult _withQuotedScope;

    void Because()
    {
        var validator = new BearerRouteConfigurationValidator();

        _valid = validator.Validate(null, Configuration(_ => { }));
        _withoutRoutes = validator.Validate(null, Configuration(_ => _.PathPrefix = string.Empty, declareRoute: false));
        _withoutAudience = validator.Validate(null, Configuration(_ => _.Audiences = []));
        _withPlainHttpIssuer = validator.Validate(null, Configuration(_ => _.Issuers = [new C.BearerIssuer { Issuer = "http://auth.example.test/" }]));
        _overlappingAnonymousPath = validator.Validate(null, Configuration(_ => _.PathPrefix = "/public/mcp"));
        _withoutBackend = validator.Validate(null, Configuration(_ => { }, backend: false));
        _withLargeClockSkew = validator.Validate(null, Configuration(_ => _.ClockSkew = TimeSpan.FromHours(1)));
        _mappingIntoReservedClaim = validator.Validate(null, Configuration(_ => _.ClaimMappings = new Dictionary<string, string> { ["urn:cratis:bearer:scope"] = "scope" }));
        _withQuotedScope = validator.Validate(null, Configuration(_ => _.RequiredScopes = ["direct:\"read"]));
    }

    [Fact] void should_accept_a_complete_route() => _valid.Succeeded.ShouldBeTrue();
    [Fact] void should_leave_a_deployment_without_bearer_routes_alone() => _withoutRoutes.Succeeded.ShouldBeTrue();
    [Fact] void should_refuse_a_route_without_an_audience() => _withoutAudience.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_plain_http_issuer_off_loopback() => _withPlainHttpIssuer.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_route_overlapping_an_anonymous_path() => _overlappingAnonymousPath.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_route_on_a_service_without_a_backend() => _withoutBackend.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_clock_skew_beyond_the_maximum() => _withLargeClockSkew.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_mapping_into_a_claim_authproxy_owns() => _mappingIntoReservedClaim.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_scope_that_is_not_a_scope_token() => _withQuotedScope.Failed.ShouldBeTrue();

    static C.AuthProxy Configuration(Action<C.BearerRoute> adjust, bool backend = true, bool declareRoute = true)
    {
        var route = new C.BearerRoute
        {
            PathPrefix = "/mcp",
            Issuers = [new C.BearerIssuer { Issuer = "https://auth.example.test/" }],
            Audiences = ["direct-api"],
            RequiredScopes = ["direct:read"],
            ResourceMetadataUrl = "https://direct.example.test/.well-known/oauth-protected-resource/mcp",
        };
        adjust(route);

        return new()
        {
            Services = new Dictionary<string, C.Service>
            {
                ["main"] = new()
                {
                    Backend = backend ? new C.ServiceEndpoint { BaseUrl = "https://backend.example.test" } : null,
                    AnonymousPaths = ["/public"],
                    BearerRoutes = declareRoute ? [route] : [],
                },
            },
        };
    }
}
