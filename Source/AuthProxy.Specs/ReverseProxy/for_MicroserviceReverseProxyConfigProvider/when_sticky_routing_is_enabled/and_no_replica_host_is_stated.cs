// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_MicroserviceReverseProxyConfigProvider.when_sticky_routing_is_enabled;

public class and_no_replica_host_is_stated : given.a_provider_over_a_sticky_service
{
    void Establish() => Provide(Configuration(replicaHost: string.Empty));

    [Fact]
    void should_use_the_host_of_the_base_url() =>
        BackendOf(_provider.GetConfig()).Destinations.Single().Value.Metadata[MicroserviceReverseProxyConfigProvider.ReplicaHostMetadataKey].ShouldEqual("reporting");
}
