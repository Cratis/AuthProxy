// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware;

public class when_starting_from_another_site : an_on_behalf_middleware
{
    void Establish()
    {
        PostStart(/*lang=json,strict*/ "{\"tenant\":\"t\",\"subject\":\"s\",\"issue\":\"i\"}");
        _context.Request.Headers["Sec-Fetch-Site"] = "cross-site";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_refuse() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
    [Fact] void should_say_why() => ResponseBody().ShouldContain("same-origin-required");
    [Fact] void should_not_start_a_session() => _sessions.DidNotReceive().Start(Arg.Any<HttpContext>(), Arg.Any<OnBehalfStartRequest>());
}
