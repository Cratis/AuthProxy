// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware;

public class when_starting_and_the_grant_is_not_live : an_on_behalf_middleware
{
    void Establish()
    {
        PostStart($$"""{ "tenant": "{{Sessions.Tenant}}", "subject": "{{Sessions.Subject}}", "issue": "{{Sessions.Issue}}" }""");
        _sessions.Start(_context, Arg.Any<OnBehalfStartRequest>()).Returns(new OnBehalfStartResult(OnBehalfStartStatus.NotGranted));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_ask_for_exactly_what_was_requested() => _sessions.Received(1).Start(_context, new OnBehalfStartRequest(Sessions.Tenant, Sessions.Subject, Sessions.Issue));
    [Fact] void should_be_forbidden() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
    [Fact] void should_say_there_is_no_grant() => ResponseBody().ShouldContain("not-granted");
    [Fact] void should_not_be_cached() => _context.Response.Headers.CacheControl.ToString().ShouldEqual("no-store");
}
