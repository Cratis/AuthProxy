// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware;

public class when_the_grant_cannot_be_rechecked : an_on_behalf_middleware
{
    void Establish() => _sessions.Resolve(_context).Returns(OnBehalfResolution.Unavailable);

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_forward_the_request() => _nextCalled.ShouldBeFalse();
    [Fact] void should_be_unavailable() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status503ServiceUnavailable);
}
