// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ReplicaDestinationResolver;

public class when_discovery_finds_no_replica : given.a_resolver
{
    void Establish() => Discovers();

    async Task Because() => _result = await Resolve();

    [Fact] void should_publish_the_seed_only() => _result.Destinations.Keys.ShouldContainOnly(SeedId);
    [Fact] void should_still_refresh() => _result.ChangeToken.ShouldNotBeNull();
}
