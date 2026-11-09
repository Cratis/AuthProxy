// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteConfigurationValidator;

/// <summary>
/// Introspection is how a revoked token stops working at the edge, so a setting that would quietly weaken it
/// is refused at startup: accepting tokens on an MCP route when the issuer cannot be asked, an endpoint that is
/// not HTTPS, no client credential, or a cache that would keep a revoked token alive longer than the bound.
/// </summary>
public class when_validating_introspection : Specification
{
    ValidateOptionsResult _valid;
    ValidateOptionsResult _acceptOnMcpRoute;
    ValidateOptionsResult _acceptOnMcpRouteWithOtherCase;
    ValidateOptionsResult _acceptOnAnotherRoute;
    ValidateOptionsResult _withoutEndpoint;
    ValidateOptionsResult _withPlainHttpEndpoint;
    ValidateOptionsResult _withLoopbackHttpEndpoint;
    ValidateOptionsResult _withoutClientId;
    ValidateOptionsResult _withoutClientSecret;
    ValidateOptionsResult _withLongCache;
    ValidateOptionsResult _withNegativeCache;
    ValidateOptionsResult _withoutCache;
    ValidateOptionsResult _withTinyTimeout;
    ValidateOptionsResult _withHugeTimeout;
    ValidateOptionsResult _withoutRoom;

    void Because()
    {
        var validator = new BearerRouteConfigurationValidator();

        _valid = validator.Validate(null, Configuration(_ => { }));
        _acceptOnMcpRoute = validator.Validate(null, Configuration(_ => _.IntrospectionUnavailable = C.IntrospectionFailurePolicy.Accept));
        _acceptOnMcpRouteWithOtherCase = validator.Validate(null, Configuration(_ => _.IntrospectionUnavailable = C.IntrospectionFailurePolicy.Accept, prefix: "/MCP/v2"));
        _acceptOnAnotherRoute = validator.Validate(null, Configuration(_ => _.IntrospectionUnavailable = C.IntrospectionFailurePolicy.Accept, prefix: "/v1"));
        _withoutEndpoint = validator.Validate(null, Configuration(_ => { }, introspection: _ => _.Endpoint = string.Empty));
        _withPlainHttpEndpoint = validator.Validate(null, Configuration(_ => { }, introspection: _ => _.Endpoint = "http://auth.example.test/connect/introspect"));
        _withLoopbackHttpEndpoint = validator.Validate(null, Configuration(_ => { }, introspection: _ => _.Endpoint = "http://127.0.0.1:5000/connect/introspect"));
        _withoutClientId = validator.Validate(null, Configuration(_ => { }, introspection: _ => _.ClientId = " "));
        _withoutClientSecret = validator.Validate(null, Configuration(_ => { }, introspection: _ => _.ClientSecret = string.Empty));
        _withLongCache = validator.Validate(null, Configuration(_ => { }, introspection: _ => _.CacheDuration = TimeSpan.FromSeconds(31)));
        _withNegativeCache = validator.Validate(null, Configuration(_ => { }, introspection: _ => _.CacheDuration = TimeSpan.FromSeconds(-1)));
        _withoutCache = validator.Validate(null, Configuration(_ => { }, introspection: _ => _.CacheDuration = TimeSpan.Zero));
        _withTinyTimeout = validator.Validate(null, Configuration(_ => { }, introspection: _ => _.Timeout = TimeSpan.FromMilliseconds(10)));
        _withHugeTimeout = validator.Validate(null, Configuration(_ => { }, introspection: _ => _.Timeout = TimeSpan.FromMinutes(1)));
        _withoutRoom = validator.Validate(null, Configuration(_ => { }, introspection: _ => _.MaximumCachedTokens = 0));
    }

    [Fact] void should_accept_a_complete_configuration() => _valid.Succeeded.ShouldBeTrue();
    [Fact] void should_refuse_accepting_tokens_on_an_mcp_route() => _acceptOnMcpRoute.Failed.ShouldBeTrue();
    [Fact] void should_name_the_setting_when_refusing_accept() => _acceptOnMcpRoute.FailureMessage.ShouldContain(nameof(C.BearerRoute.IntrospectionUnavailable));
    [Fact] void should_recognize_an_mcp_route_whatever_its_case_or_depth() => _acceptOnMcpRouteWithOtherCase.Failed.ShouldBeTrue();
    [Fact] void should_allow_accepting_tokens_on_a_route_that_is_not_mcp() => _acceptOnAnotherRoute.Succeeded.ShouldBeTrue();
    [Fact] void should_refuse_a_missing_endpoint() => _withoutEndpoint.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_plain_http_endpoint() => _withPlainHttpEndpoint.Failed.ShouldBeTrue();
    [Fact] void should_accept_a_plain_http_loopback_endpoint() => _withLoopbackHttpEndpoint.Succeeded.ShouldBeTrue();
    [Fact] void should_refuse_a_missing_client_id() => _withoutClientId.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_missing_client_secret() => _withoutClientSecret.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_cache_longer_than_the_bound() => _withLongCache.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_negative_cache() => _withNegativeCache.Failed.ShouldBeTrue();
    [Fact] void should_accept_no_cache() => _withoutCache.Succeeded.ShouldBeTrue();
    [Fact] void should_refuse_a_timeout_below_the_range() => _withTinyTimeout.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_timeout_above_the_range() => _withHugeTimeout.Failed.ShouldBeTrue();
    [Fact] void should_refuse_a_cache_without_room() => _withoutRoom.Failed.ShouldBeTrue();

    static C.AuthProxy Configuration(Action<C.BearerRoute> adjust, Action<C.BearerIssuerIntrospection>? introspection = null, string prefix = "/mcp")
    {
        var settings = new C.BearerIssuerIntrospection
        {
            Endpoint = "https://auth.example.test/connect/introspect",
            ClientId = "authproxy",
            ClientSecret = "not-a-real-secret",
        };
        introspection?.Invoke(settings);

        var route = new C.BearerRoute
        {
            PathPrefix = prefix,
            Issuers = [new C.BearerIssuer { Issuer = "https://auth.example.test/", Introspection = settings }],
            Audiences = ["direct-api"],
        };
        adjust(route);

        return new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["main"] = new C.Service
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.example.test" },
                    IdentityVerification = C.IdentityVerificationMode.BestEffort,
                    BearerRoutes = [route],
                },
            },
        };
    }
}
