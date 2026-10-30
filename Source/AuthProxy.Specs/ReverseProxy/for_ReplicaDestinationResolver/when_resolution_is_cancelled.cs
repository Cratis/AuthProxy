// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ReplicaDestinationResolver;

public class when_resolution_is_cancelled : given.a_resolver
{
    Exception _error;

    void Establish() => Discovers("10.0.0.1");

    async Task Because()
    {
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        _error = await Catch.Exception(async () => await Resolve(cancellationToken: cancelled.Token));
    }

    [Fact] void should_throw_the_cancellation() => _error.ShouldBeAssignableFrom<OperationCanceledException>();
}
