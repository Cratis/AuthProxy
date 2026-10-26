// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware;

/// <summary>
/// A bodiless POST is what a cross-site form sends. Without a same-origin marker or a JSON content type, nothing says the
/// request came from AuthProxy's own pages.
/// </summary>
public class when_ending_the_session_without_saying_where_it_came_from : an_on_behalf_middleware
{
    void Establish()
    {
        _context.Request.Method = HttpMethods.Post;
        _context.Request.Path = WellKnownPaths.OnBehalfEnd;
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_refuse() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
    [Fact] void should_not_end_the_session() => _sessions.DidNotReceive().End(Arg.Any<HttpContext>(), Arg.Any<OnBehalfSessionEndReason>());
}
