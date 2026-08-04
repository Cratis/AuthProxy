// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider;

/// <summary>
/// A service with no endpoint to forward to must not take a prefix away from a service that has one.
/// <para>
/// A <c>Services</c> entry does not have to declare a backend or a frontend — the lobby's registration
/// service is configured that way — so a declaration on such an entry produces no route. If that
/// declaration still claimed the prefix, the service that can actually serve it would be skipped, and the
/// path would match no route at all while all three middlewares went on treating it as anonymous: a
/// <c>404</c> on a path the deployment declared public, caused by a service that never even appears in the
/// route table.
/// </para>
/// </summary>
public class when_a_service_declares_a_path_it_cannot_serve : Specification
{
    MicroserviceReverseProxyConfigProvider _provider;
    IReadOnlyList<RouteConfig> _routes;

    void Establish()
    {
        var authProxy = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                // Declared first, so it is the one that would claim the prefix.
                ["Endpointless"] = new()
                {
                    Registration = new C.ServiceEndpoint { BaseUrl = "https://registration.local/" },
                    AnonymousPaths = ["/portal"],
                },
                ["Serving"] = new()
                {
                    Frontend = new C.ServiceEndpoint { BaseUrl = "https://serving.local/" },
                    AnonymousPaths = ["/portal"],
                },
            },
        };

        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(authProxy);

        _provider = new MicroserviceReverseProxyConfigProvider(monitor, Substitute.For<ILogger<MicroserviceReverseProxyConfigProvider>>());
    }

    void Because() => _routes = _provider.GetConfig().Routes;

    [Fact] void should_route_the_prefix_to_the_service_that_can_serve_it() => _routes.Single(_ => _.Match.Path == "/portal/{**catch-all}").ClusterId.ShouldEqual("serving-frontend-cluster");
    [Fact] void should_generate_no_route_for_the_service_with_no_endpoint() => _routes.Any(_ => _.ClusterId?.StartsWith("endpointless", StringComparison.Ordinal) == true).ShouldBeFalse();
}
