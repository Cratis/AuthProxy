// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.ServiceDiscovery;

namespace Cratis.AuthProxy.ReverseProxy.for_ReplicaDestinationResolver;

public class when_discovery_fails_after_replicas_were_known : given.a_resolver
{
    ResolvedDestinationCollection _first;

    void Establish() => Discovers("10.0.0.1", "10.0.0.2");

    async Task Because()
    {
        _first = await Resolve();
        Fails();
        _result = await Resolve();
    }

    [Fact] void should_keep_the_last_known_replicas() => _result.Destinations.Keys.Order().ShouldEqual(_first.Destinations.Keys.Order());
}
