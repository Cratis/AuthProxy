// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider;

/// <summary>
/// Hosts and path prefixes become routes, and route order states their precedence: a prefix on its hosts, a prefix
/// on every host, an explicit Service-ID header or service query parameter, then a host.
/// </summary>
public class when_services_declare_hosts_and_path_prefixes : Specification
{
    MicroserviceReverseProxyConfigProvider _provider;
    IReadOnlyList<RouteConfig> _routes;

    void Establish()
    {
        var authProxy = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["Reports"] = new()
                {
                    PathPrefix = "/reports/",
                    StripPathPrefix = true,
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://reports-api/" },
                    Frontend = new C.ServiceEndpoint { BaseUrl = "http://reports-web/" },
                    AnonymousPaths = ["/reports/public", "/reports/api/health"],
                },
                ["TenantReports"] = new()
                {
                    Hosts = ["tenant.example.com"],
                    PathPrefix = "/reports",
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://tenant-reports-api/" },
                },
                ["Billing"] = new()
                {
                    Hosts = ["Billing.Example.com"],
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://billing-api/" },
                    Frontend = new C.ServiceEndpoint { BaseUrl = "http://billing-web/" },
                },
            },
        };

        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(authProxy);
        _provider = new MicroserviceReverseProxyConfigProvider(monitor, Substitute.For<ILogger<MicroserviceReverseProxyConfigProvider>>());
    }

    void Because() => _routes = _provider.GetConfig().Routes;

    RouteConfig Route(string id) => _routes.Single(_ => _.RouteId == id);

    [Fact] void should_route_the_prefixed_api_to_the_backend() => Route("reports-prefix-api").Match.Path.ShouldEqual("/reports/api/{**catch-all}");
    [Fact] void should_route_the_rest_of_the_prefix_to_the_frontend() => Route("reports-prefix").ClusterId.ShouldEqual("reports-frontend-cluster");
    [Fact] void should_route_the_rest_of_a_backend_only_prefix_to_the_backend() => Route("tenantreports-prefix").ClusterId.ShouldEqual("tenantreports-backend-cluster");
    [Fact] void should_restrict_a_host_specific_prefix_to_its_hosts() => Route("tenantreports-prefix").Match.Hosts.ShouldContainOnly("tenant.example.com");
    [Fact] void should_order_a_host_specific_prefix_ahead_of_a_prefix_on_every_host() => Route("tenantreports-prefix").Order.ShouldBeLessThan(Route("reports-prefix-api").Order!.Value);
    [Fact] void should_order_a_prefix_ahead_of_an_explicit_selection() => Route("reports-prefix").Order.ShouldBeLessThan(Route("billing-backend-header-api").Order!.Value);
    [Fact] void should_order_an_explicit_selection_ahead_of_a_host() => Route("billing-frontend-query").Order.ShouldBeLessThan(Route("billing-host-api").Order!.Value);
    [Fact] void should_route_a_host_to_its_service() => Route("billing-host").Match.Hosts.ShouldContainOnly("billing.example.com");
    [Fact] void should_mark_a_stripped_prefix_on_its_routes() => Route("reports-prefix").Metadata![ServiceRoutes.StripPathPrefixMetadataKey].ShouldEqual("/reports");
    [Fact] void should_mark_an_anonymous_path_below_a_stripped_prefix() => Route("reports-anonymous-0").Metadata![ServiceRoutes.StripPathPrefixMetadataKey].ShouldEqual("/reports");
    [Fact] void should_route_an_anonymous_prefixed_api_to_the_backend() => Route("reports-anonymous-1").ClusterId.ShouldEqual("reports-backend-cluster");
    [Fact] void should_not_mark_a_prefix_that_is_kept() => Route("tenantreports-prefix").Metadata.ShouldBeNull();
    [Fact] void should_keep_routing_by_service_header() => _routes.Any(_ => _.RouteId == "reports-frontend-header").ShouldBeTrue();
    [Fact] void should_leave_no_two_routes_with_the_same_template_hosts_and_order() =>
        _routes.GroupBy(_ => (
                _.Match.Path?.ToUpperInvariant(),
                string.Join(',', _.Match.Hosts ?? []),
                _.Order,
                string.Join(',', _.Match.Headers?.SelectMany(header => header.Values ?? []) ?? []),
                string.Join(',', _.Match.QueryParameters?.SelectMany(query => query.Values ?? []) ?? [])))
            .Any(_ => _.Count() > 1)
            .ShouldBeFalse();
}
