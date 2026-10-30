// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.ServiceDiscovery;

namespace Cratis.AuthProxy.ReverseProxy.for_ReplicaDestinationResolver;

public class when_the_same_replicas_are_discovered_again : given.a_resolver
{
    ResolvedDestinationCollection _first;

    void Establish() => Discovers("10.0.0.1", "10.0.0.2");

    async Task Because()
    {
        _first = await Resolve();
        _result = await Resolve();
    }

    [Fact] void should_give_identical_ids() => _result.Destinations.Keys.Order().ShouldEqual(_first.Destinations.Keys.Order());
}
