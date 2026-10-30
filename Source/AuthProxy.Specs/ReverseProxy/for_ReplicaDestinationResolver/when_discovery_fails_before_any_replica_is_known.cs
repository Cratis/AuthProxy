// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ReplicaDestinationResolver;

public class when_discovery_fails_before_any_replica_is_known : given.a_resolver
{
    Exception _error;

    void Establish() => Fails();

    async Task Because() => _error = await Catch.Exception(async () => _result = await Resolve());

    [Fact] void should_not_throw() => _error.ShouldBeNull();
    [Fact] void should_publish_the_seed_only() => _result.Destinations.Keys.ShouldContainOnly(SeedId);
}
