// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_LinkMiddleware;

public class when_a_link_is_confirmed_with_a_get_style_query_only : given.a_link_page_context
{
    void Establish()
    {
        _context.Request.Path = $"{WellKnownPaths.Link}/github";
        _context.Request.QueryString = QueryString.Create("token", "the-link-token");
        PostForm(new Dictionary<string, string>());
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_challenge() => _authenticationService.DidNotReceiveWithAnyArgs().ChallengeAsync(default!, default, default);
    [Fact] void should_answer_bad_request() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status400BadRequest);
}
