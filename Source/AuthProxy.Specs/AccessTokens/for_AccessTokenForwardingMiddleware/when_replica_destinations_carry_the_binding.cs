// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_AccessTokenForwardingMiddleware;

public class when_replica_destinations_carry_the_binding : given.a_forwarding_middleware
{
    void Establish()
    {
        _availableDestinations = [new("bound-destination#a1"), new("bound-destination#b2")];
        _allDestinations = [new("bound-destination#a1"), new("bound-destination#b2")];
    }

    Task Because() => Invoke();

    [Fact] void should_forward_the_request() => _forwarded.ShouldBeTrue();
    [Fact] void should_obtain_a_token() => _tokens.Received(1).GetFor("session-id", Arg.Any<C.ServiceAccessToken>(), Arg.Any<CancellationToken>());
}
