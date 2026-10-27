// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware;

public class when_on_behalf_sessions_are_not_configured : an_on_behalf_middleware
{
    void Establish()
    {
        _configuration.Value.OnBehalf = null;
        PostStart("{}");
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_be_found() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status404NotFound);
    [Fact] void should_not_start_anything() => _sessions.DidNotReceive().Start(Arg.Any<HttpContext>(), Arg.Any<OnBehalfStartRequest>());
}
