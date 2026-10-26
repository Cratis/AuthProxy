// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware;

public class when_an_actor_without_a_session_registers : an_on_behalf_middleware
{
    void Establish() => _context.Request.Path = WellKnownPaths.Registration;

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_end_anything() => _sessions.DidNotReceive().End(Arg.Any<HttpContext>(), Arg.Any<OnBehalfSessionEndReason>());
    [Fact] void should_go_on() => _nextCalled.ShouldBeTrue();
}
