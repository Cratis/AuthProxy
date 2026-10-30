// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ReplicaDestinationResolver;

public class when_discovery_answers_with_another_scheme : given.a_resolver
{
    void Establish() => _discovery.Discover(Arg.Any<Uri>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
        .Returns(Task.FromResult<IReadOnlyList<Uri>>([new Uri("http://10.0.0.1:8443/"), Replica("10.0.0.2")]));

    async Task Because() => _result = await Resolve();

    [Fact] void should_keep_only_the_matching_scheme() => _result.Destinations.Values.Select(_ => _.Address).ShouldEqual(["https://10.0.0.2:8443/"]);
}
