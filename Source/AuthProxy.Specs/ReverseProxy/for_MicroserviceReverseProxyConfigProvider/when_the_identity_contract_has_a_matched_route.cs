// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider;

public class when_the_identity_contract_has_a_matched_route : Specification
{
    IReadOnlyList<RouteConfig> _routes;

    void Establish()
    {
        var config = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["Portal"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://portal-api/" },
                    Frontend = new C.ServiceEndpoint { BaseUrl = "http://portal-web/" },
                },
            },
        };
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(config);
        using var provider = new MicroserviceReverseProxyConfigProvider(monitor, Substitute.For<ILogger<MicroserviceReverseProxyConfigProvider>>());
        _routes = provider.GetConfig().Routes;
    }

    [Fact]
    void should_use_an_exact_authenticated_route()
    {
        var route = _routes.Single(route => route.RouteId == "portal-frontend-header-identity");
        route.Match.Path.ShouldEqual(WellKnownPaths.IdentityDetails);
        route.AuthorizationPolicy.ShouldEqual("default");
        route.Metadata[ReservedProxyPathMiddleware.IdentityEndpointMetadataKey].ShouldEqual(bool.TrueString);
    }

    [Fact]
    void should_preserve_the_selected_service_and_destination()
    {
        var original = _routes.Single(route => route.RouteId == "portal-frontend-header");
        var identity = _routes.Single(route => route.RouteId == "portal-frontend-header-identity");
        identity.ClusterId.ShouldEqual(original.ClusterId);
        identity.Order.ShouldEqual(original.Order);
        identity.Match.Headers.ShouldEqual(original.Match.Headers);
        identity.Metadata[ServiceSelection.RouteMetadataKey].ShouldEqual("Portal");
    }

    [Fact]
    void should_not_mark_service_catch_all_routes_as_local_contracts() =>
        _routes.Any(route => route.Match.Path == "/{**catch-all}"
            && route.Metadata.ContainsKey(ReservedProxyPathMiddleware.IdentityEndpointMetadataKey)).ShouldBeFalse();
}
