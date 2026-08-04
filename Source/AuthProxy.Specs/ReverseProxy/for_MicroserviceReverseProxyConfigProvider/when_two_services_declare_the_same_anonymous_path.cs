// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider;

/// <summary>
/// The same prefix declared by two services must produce one route, not two.
/// <para>
/// A declared prefix is matched without any service-selection header or query parameter — an anonymous
/// caller cannot be expected to send one — so two services declaring the same prefix emit two routes with
/// an identical template and an identical order. ASP.NET cannot choose between them and throws
/// <c>AmbiguousMatchException</c>, which surfaces as <c>HTTP 500</c> on the declared path: a
/// configuration mistake that is invisible at startup and takes down exactly the path it was meant to
/// open.
/// </para>
/// <para>
/// The first declaring service wins, in configuration order, so the path stays anonymous — which is what
/// both services asked for — and the route table stays unambiguous.
/// </para>
/// </summary>
public class when_two_services_declare_the_same_anonymous_path : Specification
{
    MicroserviceReverseProxyConfigProvider _provider;
    IReadOnlyList<RouteConfig> _routes;

    void Establish()
    {
        var authProxy = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["First"] = new()
                {
                    Frontend = new C.ServiceEndpoint { BaseUrl = "https://first.local/" },
                    AnonymousPaths = ["/portal"],
                },
                ["Second"] = new()
                {
                    Frontend = new C.ServiceEndpoint { BaseUrl = "https://second.local/" },

                    // Declared with a trailing slash and a different casing: the same prefix once
                    // normalized, which is the form a copy-paste between services actually takes.
                    AnonymousPaths = ["/Portal/", "/reports"],
                },
            },
        };

        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(authProxy);

        _provider = new MicroserviceReverseProxyConfigProvider(monitor);
    }

    void Because() => _routes = _provider.GetConfig().Routes;

    [Fact] void should_generate_one_route_for_the_shared_prefix() =>
        _routes.Count(_ => _.Match.Path == "/portal/{**catch-all}").ShouldEqual(1);

    [Fact] void should_award_the_shared_prefix_to_the_first_declaring_service() =>
        _routes.Single(_ => _.Match.Path == "/portal/{**catch-all}").ClusterId.ShouldEqual("first-frontend-cluster");

    [Fact] void should_still_generate_the_prefix_only_the_second_service_declares() =>
        _routes.Single(_ => _.Match.Path == "/reports/{**catch-all}").ClusterId.ShouldEqual("second-frontend-cluster");

    [Fact] void should_not_generate_two_routes_with_the_same_template_and_order() =>
        _routes.GroupBy(_ => new { _.Match.Path, _.Order })
            .Where(group => group.Any(_ => _.AuthorizationPolicy == "anonymous"))
            .All(group => group.Count() == 1)
            .ShouldBeTrue();
}
