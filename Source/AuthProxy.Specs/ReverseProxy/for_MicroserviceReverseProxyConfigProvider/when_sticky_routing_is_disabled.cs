// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider;

public class when_sticky_routing_is_disabled : Specification
{
    ClusterConfig _absent;
    ClusterConfig _disabled;

    static ClusterConfig BackendOf(C.StickyRouting? sticky)
    {
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["Reporting"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://reporting:8080/", StickyRouting = sticky },
                    AccessToken = new C.ServiceAccessToken { Scopes = ["api://reporting"] },
                },
            },
        });
        using var provider = new MicroserviceReverseProxyConfigProvider(monitor, Substitute.For<ILogger<MicroserviceReverseProxyConfigProvider>>());
        return provider.GetConfig().Clusters.Single();
    }

    void Because()
    {
        _absent = BackendOf(null);
        _disabled = BackendOf(new C.StickyRouting { Enabled = false, ReplicaHost = "ignored.svc" });
    }

    [Fact] void should_build_the_cluster_it_would_without_the_setting() => _disabled.ShouldEqual(_absent);
    [Fact] void should_not_enable_session_affinity() => _disabled.SessionAffinity.ShouldBeNull();
    [Fact] void should_not_enable_health_checks() => _disabled.HealthCheck.ShouldBeNull();
    [Fact] void should_keep_the_destination_metadata_free() => _disabled.Destinations.Single().Value.Metadata.ShouldBeNull();
}
