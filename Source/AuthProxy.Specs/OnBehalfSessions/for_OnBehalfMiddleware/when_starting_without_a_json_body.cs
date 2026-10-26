// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware;

/// <summary>
/// A cross-site form can post a form body, never a JSON one without a preflight. Requiring JSON is what keeps another
/// site from making a support person's browser start a session.
/// </summary>
public class when_starting_without_a_json_body : an_on_behalf_middleware
{
    void Establish() => PostStart("tenant=t&subject=s&issue=i", "application/x-www-form-urlencoded");

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_refuse_the_media_type() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status415UnsupportedMediaType);
    [Fact] void should_not_start_anything() => _sessions.DidNotReceive().Start(Arg.Any<HttpContext>(), Arg.Any<OnBehalfStartRequest>());
    [Fact] void should_never_reach_the_application() => _nextCalled.ShouldBeFalse();
}
