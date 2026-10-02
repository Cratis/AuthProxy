// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_AccessTokenForwardingMiddleware;

public class when_all_destinations_include_a_stale_binding : given.a_forwarding_middleware
{
    void Establish() => _allDestinations = [new("bound-destination"), new("stale-destination")];

    Task Because() => Invoke();

    [Fact] void should_refuse_the_mixed_snapshot() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status503ServiceUnavailable);
    [Fact] void should_not_obtain_a_token() => _tokens.DidNotReceive().GetFor(Arg.Any<string>(), Arg.Any<C.ServiceAccessToken>(), Arg.Any<CancellationToken>());
    [Fact] void should_not_forward_the_request() => _forwarded.ShouldBeFalse();
}
