// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.ServiceDiscovery;

namespace Cratis.AuthProxy.ReverseProxy.for_ReplicaDestinationResolver;

public class when_a_replica_disappears : given.a_resolver
{
    ResolvedDestinationCollection _first;

    void Establish() => Discovers("10.0.0.1", "10.0.0.2");

    async Task Because()
    {
        _first = await Resolve();
        Discovers("10.0.0.1");
        _result = await Resolve();
    }

    [Fact] void should_publish_one_replica() => _result.Destinations.Count.ShouldEqual(1);
    [Fact] void should_keep_the_id_of_the_remaining_replica() => _first.Destinations.Keys.ShouldContain(_result.Destinations.Keys.Single());
    [Fact] void should_drop_the_other_id() => _first.Destinations.Keys.Count(_result.Destinations.ContainsKey).ShouldEqual(1);
}
