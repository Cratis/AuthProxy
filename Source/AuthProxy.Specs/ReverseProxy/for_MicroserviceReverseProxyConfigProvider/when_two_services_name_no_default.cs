// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider;

/// <summary>
/// Without a service that says it is the default, several services keep the behavior they always had: no catch-all.
/// </summary>
public class when_two_services_name_no_default : Specification
{
    IReadOnlyList<RouteConfig> _routes;

    void Because()
    {
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["direct"] = new() { Frontend = new C.ServiceEndpoint { BaseUrl = "http://direct/" } },
                ["runners"] = new() { PathPrefix = "/runners", Backend = new C.ServiceEndpoint { BaseUrl = "http://direct:8082/" } },
            },
        });
        using var provider = new MicroserviceReverseProxyConfigProvider(monitor, Substitute.For<ILogger<MicroserviceReverseProxyConfigProvider>>());
        _routes = provider.GetConfig().Routes;
    }

    [Fact] void should_add_no_catch_all() => _routes.ShouldNotContain(_ => _.RouteId.EndsWith("catchall-default", StringComparison.Ordinal));
}
