// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_LinkMiddleware;

public class when_a_link_is_confirmed_without_a_valid_antiforgery_token : given.a_link_page_context
{
    protected override bool AntiforgeryIsValid => false;

    void Establish()
    {
        _context.Request.Path = $"{WellKnownPaths.Link}/github";
        _context.Request.QueryString = QueryString.Create("token", "the-link-token");
        PostForm(new Dictionary<string, string> { ["token"] = "the-link-token" });
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_challenge() => _authenticationService.DidNotReceiveWithAnyArgs().ChallengeAsync(default!, default, default);
    [Fact] void should_answer_bad_request() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status400BadRequest);
}
