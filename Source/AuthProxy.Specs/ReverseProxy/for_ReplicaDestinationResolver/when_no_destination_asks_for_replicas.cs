// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy.for_ReplicaDestinationResolver;

public class when_no_destination_asks_for_replicas : given.a_resolver
{
    Dictionary<string, DestinationConfig> _destinations;

    async Task Because()
    {
        _destinations = new() { ["destination1"] = new() { Address = "http://plain/" } };
        _result = await Resolve(_destinations);
    }

    [Fact] void should_return_the_same_destinations() => ReferenceEquals(_result.Destinations, _destinations).ShouldBeTrue();
    [Fact] void should_not_set_a_change_token() => _result.ChangeToken.ShouldBeNull();
    [Fact] void should_not_discover() => _discovery.DidNotReceiveWithAnyArgs().Discover(default!, default!, TestContext.Current.CancellationToken);
}
