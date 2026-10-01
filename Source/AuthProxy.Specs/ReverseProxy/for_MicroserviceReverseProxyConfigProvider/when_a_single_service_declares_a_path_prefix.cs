// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider;

/// <summary>
/// A single service normally gets plain catch-all routes, but one that declares a path prefix asked to be reached
/// through it, so nothing outside the prefix is routed to it.
/// </summary>
public class when_a_single_service_declares_a_path_prefix : Specification
{
    MicroserviceReverseProxyConfigProvider _provider;

    void Establish()
    {
        var authProxy = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["Reports"] = new()
                {
                    PathPrefix = "/reports",
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://reports-api/" },
                    Frontend = new C.ServiceEndpoint { BaseUrl = "http://reports-web/" },
                },
            },
        };

        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(authProxy);
        _provider = new MicroserviceReverseProxyConfigProvider(monitor, Substitute.For<ILogger<MicroserviceReverseProxyConfigProvider>>());
    }

    [Fact] void should_not_add_the_single_service_catch_all_routes() =>
        _provider.GetConfig().Routes.Any(_ => _.RouteId.EndsWith("-default", StringComparison.OrdinalIgnoreCase)).ShouldBeFalse();

    [Fact] void should_route_the_prefix() => _provider.GetConfig().Routes.Any(_ => _.RouteId == "reports-prefix").ShouldBeTrue();
}
