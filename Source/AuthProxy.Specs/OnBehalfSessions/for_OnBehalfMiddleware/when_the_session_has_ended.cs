// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware;

/// <summary>
/// A request whose session ended is refused, never quietly forwarded as the actor instead.
/// </summary>
public class when_the_session_has_ended : an_on_behalf_middleware
{
    void Establish() =>
        _sessions.Resolve(_context).Returns(new OnBehalfResolution(OnBehalfResolutionStatus.Ended, Reason: OnBehalfSessionEndReason.GrantNotLive));

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_forward_the_request() => _nextCalled.ShouldBeFalse();
    [Fact] void should_refuse_it() => _errorPages.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.Forbidden, StatusCodes.Status403Forbidden);
    [Fact] void should_say_why_it_ended() => _context.Response.Headers[Headers.OnBehalfEnded].ToString().ShouldEqual("grant-not-live");
}
