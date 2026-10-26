// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware;

/// <summary>
/// Another site must not be able to end a support person's session from their browser.
/// </summary>
public class when_ending_the_session_from_another_origin : an_on_behalf_middleware
{
    void Establish()
    {
        _context.Request.Method = HttpMethods.Post;
        _context.Request.Path = WellKnownPaths.OnBehalfEnd;
        _context.Request.Scheme = "https";
        _context.Request.Host = new HostString("app.example.com");
        _context.Request.Headers.Origin = "https://elsewhere.example.com";
        _context.Request.ContentType = "application/json";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_refuse() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
    [Fact] void should_say_why() => ResponseBody().ShouldContain("same-origin-required");
    [Fact] void should_not_end_the_session() => _sessions.DidNotReceive().End(Arg.Any<HttpContext>(), Arg.Any<OnBehalfSessionEndReason>());
}
