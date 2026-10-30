// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_AccessTokenForwardingMiddleware;

public class when_a_replica_destination_carries_a_stale_binding : given.a_forwarding_middleware
{
    void Establish()
    {
        _availableDestinations = [new("bound-destination#a1"), new("stale-destination#b2")];
        _allDestinations = [new("bound-destination#a1"), new("stale-destination#b2")];
    }

    Task Because() => Invoke();

    [Fact] void should_refuse_the_mixed_snapshot() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status503ServiceUnavailable);
    [Fact] void should_not_obtain_a_token() => _tokens.DidNotReceive().GetFor(Arg.Any<string>(), Arg.Any<C.ServiceAccessToken>(), Arg.Any<CancellationToken>());
    [Fact] void should_not_forward_the_request() => _forwarded.ShouldBeFalse();
}
