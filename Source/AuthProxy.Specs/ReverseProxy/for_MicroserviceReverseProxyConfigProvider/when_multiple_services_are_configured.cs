// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider;

public class when_multiple_services_are_configured : Specification
{
    MicroserviceReverseProxyConfigProvider _provider;

    void Establish()
    {
        var authProxy = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["ServiceA"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "https://service-a-backend.local/" },
                    Frontend = new C.ServiceEndpoint { BaseUrl = "https://service-a-frontend.local/" }
                },
                ["ServiceB"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "https://service-b-backend.local/" },
                }
            }
        };

        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(authProxy);

        _provider = new MicroserviceReverseProxyConfigProvider(monitor);
    }

    [Fact] void should_not_include_single_service_default_routes() =>
        _provider.GetConfig().Routes.Any(_ => _.RouteId.EndsWith("-default", StringComparison.OrdinalIgnoreCase)).ShouldBeFalse();

    [Fact] void should_include_expected_clusters_for_each_service_endpoint() =>
        _provider.GetConfig().Clusters.Select(_ => _.ClusterId).ShouldContain([
            "servicea-backend-cluster",
            "servicea-frontend-cluster",
            "serviceb-backend-cluster"
        ]);
}
