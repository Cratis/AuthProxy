// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_AccessTokenForwardingMiddleware;

public class when_the_session_holds_no_token_session : given.a_forwarding_middleware
{
    void Establish() => _context.Items.Remove(UserTokenSessions.HttpContextItemKey);

    Task Because() => Invoke();

    [Fact] void should_not_forward_the_request() => _forwarded.ShouldBeFalse();
    [Fact] void should_refuse_it_as_unauthenticated() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);
}
