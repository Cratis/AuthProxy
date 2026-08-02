// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider;

/// <summary>
/// An entry that is not a rooted path of literal segments must produce no route at all.
/// <para>
/// A declared prefix is interpolated into an ASP.NET route template, so an unvalidated entry would be
/// read as template syntax rather than as a literal: <c>/route{parameter}</c> would match
/// <c>/routeanything/…</c> anonymously, and <c>//double</c> or <c>/catch/{**all}</c> is not a legal
/// template at all and would fail the proxy's configuration load at startup. Neither can be reached from
/// configuration, and this pins that the route table sees exactly what the middlewares see.
/// </para>
/// </summary>
public class when_declared_anonymous_paths_are_unusable : Specification
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
                    AnonymousPaths =
                    [
                        string.Empty,
                        "   ",
                        "/",
                        "//double",
                        "unrooted",
                        "/route{parameter}",
                        "/catch/{**all}",
                        "/query?token=1",
                    ],
                },
            },
        };

        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(authProxy);

        _provider = new MicroserviceReverseProxyConfigProvider(monitor);
    }

    void Because() => _routes = _provider.GetConfig().Routes;

    [Fact] void should_generate_no_anonymous_routes() =>
        _routes.Any(_ => _.RouteId.StartsWith("app-anonymous-", StringComparison.Ordinal)).ShouldBeFalse();

    [Fact] void should_leave_every_route_requiring_an_authenticated_user() =>
        _routes.All(_ => _.AuthorizationPolicy == "default").ShouldBeTrue();

    [Fact] void should_produce_the_same_routes_as_a_service_declaring_nothing() =>
        _routes.Select(_ => _.RouteId).ShouldContainOnly(RouteIdsWithoutAnyDeclaration());

    static IEnumerable<string> RouteIdsWithoutAnyDeclaration()
    {
        var authProxy = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["App"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.local/" },
                    Frontend = new C.ServiceEndpoint { BaseUrl = "https://frontend.local/" },
                },
            },
        };

        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(authProxy);

        return new MicroserviceReverseProxyConfigProvider(monitor).GetConfig().Routes.Select(_ => _.RouteId);
    }
}
