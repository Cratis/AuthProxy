// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider;

public class when_single_service_has_backend_and_frontend : Specification
{
    MicroserviceReverseProxyConfigProvider _provider;

    void Establish()
    {
        var authProxy = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["App"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.local/" },
                    Frontend = new C.ServiceEndpoint { BaseUrl = "https://frontend.local/" }
                }
            }
        };

        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(authProxy);

        _provider = new MicroserviceReverseProxyConfigProvider(monitor);
    }

    [Fact] void should_include_backend_default_api_route() =>
        _provider.GetConfig().Routes.Any(_ => _.RouteId == "app-backend-api-default").ShouldBeTrue();

    [Fact] void should_include_frontend_catch_all_default_route() =>
        _provider.GetConfig().Routes.Any(_ => _.RouteId == "app-frontend-catchall-default").ShouldBeTrue();

    [Fact] void should_include_both_backend_and_frontend_clusters() =>
        _provider.GetConfig().Clusters.Select(_ => _.ClusterId).ShouldContain([
            "app-backend-cluster",
            "app-frontend-cluster"
        ]);
}
