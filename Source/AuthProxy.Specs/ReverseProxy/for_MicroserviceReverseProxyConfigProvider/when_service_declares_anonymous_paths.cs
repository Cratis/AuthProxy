// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider;

/// <summary>
/// A declared anonymous path must produce a route that relaxes the authorization policy, and nothing else
/// in the table may be relaxed with it.
/// <para>
/// Every other generated route carries <c>AuthorizationPolicy = "default"</c>, which is
/// <c>RequireAuthenticatedUser()</c>. Clearing <c>SelectProviderMiddleware</c> and <c>TenancyMiddleware</c>
/// gets a request as far as authorization and no further, so this is the third of the three places that
/// have to agree before a declared path is actually reachable.
/// </para>
/// </summary>
public class when_service_declares_anonymous_paths : Specification
{
    MicroserviceReverseProxyConfigProvider _provider;
    IReadOnlyList<RouteConfig> _routes;

    void Establish()
    {
        var authProxy = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["App"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.local/" },
                    Frontend = new C.ServiceEndpoint { BaseUrl = "https://frontend.local/" },
                    AnonymousPaths = ["/portal", "/api/reports/public"],
                },
            },
        };

        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(authProxy);

        _provider = new MicroserviceReverseProxyConfigProvider(monitor, Substitute.For<ILogger<MicroserviceReverseProxyConfigProvider>>());
    }

    void Because() => _routes = _provider.GetConfig().Routes;

    [Fact] void should_generate_one_route_per_declared_path() =>
        _routes.Count(_ => _.RouteId.StartsWith("app-anonymous-", StringComparison.Ordinal)).ShouldEqual(2);

    [Fact] void should_serve_the_frontend_prefix_from_the_frontend_cluster() =>
        _routes.Single(_ => _.Match.Path == "/portal/{**catch-all}").ClusterId.ShouldEqual("app-frontend-cluster");

    [Fact] void should_serve_the_api_prefix_from_the_backend_cluster() =>
        _routes.Single(_ => _.Match.Path == "/api/reports/public/{**catch-all}").ClusterId.ShouldEqual("app-backend-cluster");

    [Fact] void should_relax_the_authorization_policy_on_the_declared_routes() =>
        _routes.Where(_ => _.RouteId.StartsWith("app-anonymous-", StringComparison.Ordinal))
            .ShouldContainOnly(_routes.Where(_ => _.AuthorizationPolicy == "anonymous"));

    [Fact] void should_keep_the_default_policy_on_every_other_route() =>
        _routes.Where(_ => !_.RouteId.StartsWith("app-anonymous-", StringComparison.Ordinal))
            .All(_ => _.AuthorizationPolicy == "default").ShouldBeTrue();

    [Fact] void should_order_the_declared_routes_ahead_of_every_other_route() =>
        _routes.Where(_ => _.RouteId.StartsWith("app-anonymous-", StringComparison.Ordinal))
            .All(anonymous => _routes
                .Where(other => !other.RouteId.StartsWith("app-anonymous-", StringComparison.Ordinal))
                .All(other => anonymous.Order < other.Order))
            .ShouldBeTrue();

    [Fact] void should_not_constrain_the_declared_routes_by_service_selection() =>
        _routes.Where(_ => _.RouteId.StartsWith("app-anonymous-", StringComparison.Ordinal))
            .All(_ => _.Match.Headers is null && _.Match.QueryParameters is null)
            .ShouldBeTrue();
}
