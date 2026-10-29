// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider;

public class when_query_selectors_are_configured : Specification
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
                    Frontend = new C.ServiceEndpoint { BaseUrl = "http://portal-web/" }
                },
                ["Admin"] = new() { Backend = new C.ServiceEndpoint { BaseUrl = "http://admin-api/" } }
            }
        };
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(config);
        var provider = new MicroserviceReverseProxyConfigProvider(monitor, Substitute.For<ILogger<MicroserviceReverseProxyConfigProvider>>());
        _routes = provider.GetConfig().Routes;
    }

    [Theory]
    [InlineData("portal-backend-canonical-query-api", "x-cratis-microservice", "portal-backend-cluster", 11)]
    [InlineData("portal-backend-query-api", "service", "portal-backend-cluster", 12)]
    [InlineData("portal-frontend-canonical-query", "x-cratis-microservice", "portal-frontend-cluster", 21)]
    [InlineData("portal-frontend-query", "service", "portal-frontend-cluster", 22)]
    public void should_generate_exact_case_insensitive_authorized_service_routes(string id, string key, string cluster, int order)
    {
        var route = _routes.Single(_ => _.RouteId == id);
        route.ClusterId.ShouldEqual(cluster);
        route.Metadata[ServiceSelection.RouteMetadataKey].ShouldEqual("Portal");
        route.AuthorizationPolicy.ShouldEqual("default");
        route.Order.ShouldEqual(order);
        var expectedPath = cluster == "portal-backend-cluster" ? "/api/{**catch-all}" : "/{**catch-all}";
        route.Match.Path.ShouldEqual(expectedPath);
        var selector = route.Match.QueryParameters.Single();
        selector.Name.ShouldEqual(key);
        selector.Mode.ShouldEqual(QueryParameterMatchMode.Exact);
        selector.IsCaseSensitive.ShouldBeFalse();
        selector.Values.Single().ShouldEqual("portal");
    }

    [Fact] void should_keep_header_routes_first() => _routes.Single(_ => _.RouteId == "portal-backend-header-api").Order.ShouldEqual(10);

    [Fact] void should_keep_frontend_headers_after_backend_queries() => _routes.Single(_ => _.RouteId == "portal-frontend-header").Order.ShouldEqual(20);

    [Fact] void should_keep_route_ids_unique() => _routes.Select(_ => _.RouteId).Distinct().Count().ShouldEqual(_routes.Count);

    [Fact] void should_not_add_unrestricted_defaults() => _routes.Any(_ => _.RouteId.EndsWith("-default", StringComparison.Ordinal)).ShouldBeFalse();
}
