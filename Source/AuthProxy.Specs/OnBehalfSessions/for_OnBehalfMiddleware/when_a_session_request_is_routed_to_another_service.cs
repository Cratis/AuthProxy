// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware;

/// <summary>
/// The represented user's identity only ever reaches the services the session was granted for. A request routed
/// anywhere else is refused, and the session goes on.
/// </summary>
public class when_a_session_request_is_routed_to_another_service : an_on_behalf_middleware
{
    void Establish()
    {
        RouteTo("billing");
        _sessions.Resolve(_context).Returns(new OnBehalfResolution(
            OnBehalfResolutionStatus.Active,
            new(Sessions.At(DateTimeOffset.UtcNow), Sessions.Represented(), "actor", Substitute.For<IOnBehalfAttestations>())));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_refuse_the_request() => _errorPages.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.Forbidden, StatusCodes.Status403Forbidden);
    [Fact] void should_say_the_service_is_not_permitted() => _context.Response.Headers[Headers.OnBehalfRefused].ToString().ShouldEqual(OnBehalfMiddleware.ServiceNotPermitted);
    [Fact] void should_not_forward_the_request() => _nextCalled.ShouldBeFalse();
    [Fact] void should_not_put_the_session_on_the_request() => _context.TryGetOnBehalf(out _).ShouldBeFalse();
    [Fact] void should_not_end_the_session() => _sessions.DidNotReceive().End(Arg.Any<HttpContext>(), Arg.Any<OnBehalfSessionEndReason>());
}
