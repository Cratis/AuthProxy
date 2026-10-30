// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Logging.Abstractions;

namespace Cratis.AuthProxy.ReverseProxy.for_ReplicaDestinationResolver;

public class when_discovery_does_not_answer_in_time : given.a_resolver
{
    void Establish()
    {
        _resolver.Dispose();
        _resolver = new(_discovery, TimeProvider.System, NullLogger<ReplicaDestinationResolver>.Instance) { DiscoveryTimeout = TimeSpan.FromMilliseconds(1) };
        _discovery.Discover(Arg.Any<Uri>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(async call =>
            {
                await Task.Delay(Timeout.Infinite, call.Arg<CancellationToken>());
                return [];
            });
    }

    async Task Because() => _result = await Resolve();

    [Fact] void should_publish_the_seed_only() => _result.Destinations.Keys.ShouldContainOnly(SeedId);
}
