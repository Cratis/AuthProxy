// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware;

/// <summary>
/// A client that is not a browser sends no origin headers. A JSON content type is still something a cross-site form
/// cannot send, so it is enough.
/// </summary>
public class when_ending_the_session_with_a_json_request : an_on_behalf_middleware
{
    void Establish()
    {
        _context.Request.Method = HttpMethods.Post;
        _context.Request.Path = WellKnownPaths.OnBehalfEnd;
        _context.Request.ContentType = "application/json";
        _sessions.End(_context, OnBehalfSessionEndReason.EndedByActor).Returns(OnBehalfEndStatus.Ended);
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_end_it() => _sessions.Received(1).End(_context, OnBehalfSessionEndReason.EndedByActor);
    [Fact] void should_answer_with_no_content() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status204NoContent);
}
