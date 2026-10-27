// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware;

public class when_ending_the_session : an_on_behalf_middleware
{
    void Establish()
    {
        _context.Request.Method = HttpMethods.Post;
        _context.Request.Path = WellKnownPaths.OnBehalfEnd;
        _context.Request.Headers["Sec-Fetch-Site"] = "same-origin";
        _sessions.End(_context, OnBehalfSessionEndReason.EndedByActor).Returns(OnBehalfEndStatus.Ended);
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_end_it_as_the_actor() => _sessions.Received(1).End(_context, OnBehalfSessionEndReason.EndedByActor);
    [Fact] void should_answer_with_no_content() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status204NoContent);
}
