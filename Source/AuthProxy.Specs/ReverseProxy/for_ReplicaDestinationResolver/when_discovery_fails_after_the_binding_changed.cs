// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy.for_ReplicaDestinationResolver;

public class when_discovery_fails_after_the_binding_changed : given.a_resolver
{
    void Establish() => Discovers("10.0.0.1", "10.0.0.2");

    async Task Because()
    {
        await Resolve();
        Fails();
        _result = await Resolve(new Dictionary<string, DestinationConfig> { ["core-backend-destination-new"] = Seed("https://core-new:8443/") });
    }

    [Fact] void should_publish_the_new_seed_only() => _result.Destinations.Keys.ShouldContainOnly("core-backend-destination-new");
}
