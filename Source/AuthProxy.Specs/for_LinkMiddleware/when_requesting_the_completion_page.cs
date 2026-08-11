// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_LinkMiddleware;

/// <summary>
/// The completion page ends the provider window of a successful link: it broadcasts the outcome to the
/// embedding selection page and closes. A completed link ends here — no further challenge, no sign-in
/// machinery, no loop.
/// </summary>
public class when_requesting_the_completion_page : given.a_link_page_context
{
    void Establish() => _context.Request.Path = WellKnownPaths.LinkComplete;

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_answer_with_the_completion_page() => ResponseBody().ShouldContain("Sign-In Method Added");
    [Fact] void should_answer_ok() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status200OK);
    [Fact] void should_not_challenge() => _authenticationService.DidNotReceiveWithAnyArgs().ChallengeAsync(default!, default, default);
    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
}
