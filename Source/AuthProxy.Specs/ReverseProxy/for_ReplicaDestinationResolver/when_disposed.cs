// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ReplicaDestinationResolver;

public class when_disposed : given.a_resolver
{
    Exception _error;

    void Establish() => Discovers("10.0.0.1");

    async Task Because()
    {
        _result = await Resolve();
        _error = Catch.Exception(_resolver.Dispose);
    }

    [Fact] void should_not_throw() => _error.ShouldBeNull();
    [Fact] void should_not_trigger_a_re_resolution() => _result.ChangeToken.HasChanged.ShouldBeFalse();
}
