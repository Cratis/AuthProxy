// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider;

/// <summary>
/// A second service under its own prefix - a gRPC endpoint, say - does not take the catch-all routes from the service
/// that says it is the default, and the prefix still wins on its own paths.
/// </summary>
public class when_a_default_service_sits_beside_a_prefixed_one : Specification
{
    IReadOnlyList<RouteConfig> _routes;

    void Because()
    {
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["direct"] = new()
                {
                    Default = true,
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://direct/" },
                    Frontend = new C.ServiceEndpoint { BaseUrl = "http://direct/" },
                },
                ["runners"] = new()
                {
                    PathPrefix = "/direct.runners.Runner",
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://direct:8082/", Protocol = C.BackendProtocol.Http2 },
                },
            },
        });
        using var provider = new MicroserviceReverseProxyConfigProvider(monitor, Substitute.For<ILogger<MicroserviceReverseProxyConfigProvider>>());
        _routes = provider.GetConfig().Routes;
    }

    RouteConfig Route(string id) => _routes.Single(_ => _.RouteId == id);

    [Fact] void should_send_every_other_path_to_the_default_frontend() => Route("direct-frontend-catchall-default").ClusterId.ShouldEqual("direct-frontend-cluster");
    [Fact] void should_send_the_api_to_the_default_backend() => Route("direct-backend-api-default").ClusterId.ShouldEqual("direct-backend-cluster");
    [Fact] void should_send_the_prefix_to_its_own_service() => Route("runners-prefix").ClusterId.ShouldEqual("runners-backend-cluster");
    [Fact] void should_order_the_prefix_ahead_of_the_catch_all() => Route("runners-prefix").Order.ShouldBeLessThan(Route("direct-frontend-catchall-default").Order!.Value);
    [Fact] void should_give_the_prefixed_service_no_catch_all() => _routes.ShouldNotContain(_ => _.RouteId.StartsWith("runners-", StringComparison.Ordinal) && _.RouteId.Contains("default", StringComparison.Ordinal));
}
