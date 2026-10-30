// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider.when_sticky_routing_is_enabled;

public class and_the_service_declares_an_access_token : given.a_provider_over_a_sticky_service
{
    ClusterConfig _sticky;
    ClusterConfig _plain;
    ClusterConfig _otherHost;

    void Because()
    {
        Provide(Configuration(accessToken: true));
        _sticky = BackendOf(_provider.GetConfig());
        Provide(Configuration(sticky: false, accessToken: true));
        _plain = BackendOf(_provider.GetConfig());
        Provide(Configuration(replicaHost: "other-headless.svc", accessToken: true));
        _otherHost = BackendOf(_provider.GetConfig());
    }

    [Fact] void should_bind_the_seed_destination() => _sticky.Metadata[MicroserviceReverseProxyConfigProvider.DestinationMetadataKey].ShouldEqual(_sticky.Destinations.Single().Key);
    [Fact] void should_bind_differently_than_without_sticky_routing() => _sticky.Destinations.Single().Key.ShouldNotEqual(_plain.Destinations.Single().Key);
    [Fact] void should_bind_differently_when_the_replica_host_changes() => _sticky.Destinations.Single().Key.ShouldNotEqual(_otherHost.Destinations.Single().Key);
}
