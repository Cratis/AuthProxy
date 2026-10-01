// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider;

/// <summary>
/// Each cluster names the service and endpoint it belongs to, so the proxy pipeline can tell a service's backend
/// from its frontend without parsing cluster identifiers.
/// </summary>
public class when_building_clusters : Specification
{
    IReadOnlyList<ClusterConfig> _clusters;

    void Establish()
    {
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["Reporting"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://reporting-api/" },
                    Frontend = new C.ServiceEndpoint { BaseUrl = "http://reporting-web/" },
                },
            },
        });
        _clusters = new MicroserviceReverseProxyConfigProvider(monitor, Substitute.For<ILogger<MicroserviceReverseProxyConfigProvider>>()).GetConfig().Clusters;
    }

    ClusterConfig Cluster(string id) => _clusters.Single(_ => _.ClusterId == id);

    [Fact] void should_name_the_service_of_the_backend() => Cluster("reporting-backend-cluster").Metadata![MicroserviceReverseProxyConfigProvider.ServiceMetadataKey].ShouldEqual("reporting");
    [Fact] void should_mark_the_backend() => Cluster("reporting-backend-cluster").Metadata![MicroserviceReverseProxyConfigProvider.EndpointMetadataKey].ShouldEqual(MicroserviceReverseProxyConfigProvider.BackendEndpoint);
    [Fact] void should_mark_the_frontend() => Cluster("reporting-frontend-cluster").Metadata![MicroserviceReverseProxyConfigProvider.EndpointMetadataKey].ShouldEqual(MicroserviceReverseProxyConfigProvider.FrontendEndpoint);
}
