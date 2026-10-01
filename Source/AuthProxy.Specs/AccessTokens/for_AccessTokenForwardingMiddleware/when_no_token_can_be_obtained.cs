// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_AccessTokenForwardingMiddleware;

public class when_no_token_can_be_obtained : given.a_forwarding_middleware
{
    void Establish() => _tokens.GetFor("session-id", _accessToken, Arg.Any<CancellationToken>()).Returns(UserAccessTokenResult.Failed(UserAccessTokenFailure.RefreshTokenRejected));

    Task Because() => Invoke();

    [Fact] void should_not_forward_the_request() => _forwarded.ShouldBeFalse();
    [Fact] void should_refuse_it_as_unauthenticated() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);
}
