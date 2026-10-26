// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware;

/// <summary>
/// An invitation acts on the signed-in person's own account. It must never be accepted as the represented user, so
/// the session ends and the invitation goes on as the actor.
/// </summary>
public class when_a_session_enters_an_invitation : an_on_behalf_middleware
{
    void Establish()
    {
        _context.Request.Path = $"{WellKnownPaths.InvitePathPrefix}/some-token";
        _context.Request.Headers.Cookie = $"{Cookies.OnBehalf}=protected";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_end_the_session() => _sessions.Received(1).End(_context, OnBehalfSessionEndReason.IdentityFlowStarted);
    [Fact] void should_say_why_it_ended() => _context.Response.Headers[Headers.OnBehalfEnded].ToString().ShouldEqual("identity-flow-started");
    [Fact] void should_not_act_on_behalf_of_anybody() => _sessions.DidNotReceive().Resolve(Arg.Any<HttpContext>());
    [Fact] void should_go_on_as_the_actor() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_put_a_session_on_the_request() => _context.TryGetOnBehalf(out _).ShouldBeFalse();
}
