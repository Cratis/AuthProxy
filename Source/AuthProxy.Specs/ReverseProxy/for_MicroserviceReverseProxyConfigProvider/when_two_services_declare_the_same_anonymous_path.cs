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
/// both services asked for — and the route table stays unambiguous. The losing declaration is logged as a
/// warning naming both services, which is not asserted here because logging is deliberately not specced.
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

        _provider = new MicroserviceReverseProxyConfigProvider(monitor, Substitute.For<ILogger<MicroserviceReverseProxyConfigProvider>>());
    }

    void Because() => _routes = _provider.GetConfig().Routes;

    /// <summary>
    /// Determines whether no two routes carrying the anonymous policy share a template and an order.
    /// </summary>
    /// <returns><see langword="true"/> when the router can choose between every generated route.</returns>
    bool AnonymousRouteTemplatesAreUnique() =>
        _routes.GroupBy(_ => new { Path = _.Match.Path?.ToUpperInvariant(), _.Order })
            .Where(group => group.Any(_ => _.AuthorizationPolicy == "anonymous"))
            .All(group => group.Count() == 1);

    /// <summary>
    /// Finds the routes carrying a template, compared the way the router compares it.
    /// </summary>
    /// <param name="path">The route template to look for.</param>
    /// <returns>Every route whose template matches, ignoring case.</returns>
    /// <remarks>
    /// A declared prefix is not lower-cased on the way in, so an ordinal comparison would see
    /// <c>/portal</c> and <c>/Portal</c> as two different templates and miss the collision entirely —
    /// while ASP.NET, matching case-insensitively, still cannot choose between them.
    /// </remarks>
    IEnumerable<RouteConfig> RoutesMatching(string path) =>
        _routes.Where(_ => string.Equals(_.Match.Path, path, StringComparison.OrdinalIgnoreCase));

    [Fact] void should_generate_one_route_for_the_shared_prefix() => RoutesMatching("/portal/{**catch-all}").Count().ShouldEqual(1);
    [Fact] void should_award_the_shared_prefix_to_the_first_declaring_service() => RoutesMatching("/portal/{**catch-all}").Single().ClusterId.ShouldEqual("first-frontend-cluster");
    [Fact] void should_still_generate_the_prefix_only_the_second_service_declares() => RoutesMatching("/reports/{**catch-all}").Single().ClusterId.ShouldEqual("second-frontend-cluster");
    [Fact] void should_not_generate_two_routes_with_the_same_template_and_order() => AnonymousRouteTemplatesAreUnique().ShouldBeTrue();
}
