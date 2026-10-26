// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware;

public class when_a_session_request_is_routed_to_the_granting_service : an_on_behalf_middleware
{
    void Establish()
    {
        RouteTo(OnBehalfConfiguration.ServiceName);
        _sessions.Resolve(_context).Returns(new OnBehalfResolution(
            OnBehalfResolutionStatus.Active,
            new(Sessions.At(DateTimeOffset.UtcNow), Sessions.Represented(), "actor", "assertion")));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_forward_the_request() => _nextCalled.ShouldBeTrue();
    [Fact] void should_put_the_session_on_the_request() => _context.TryGetOnBehalf(out _).ShouldBeTrue();
}
