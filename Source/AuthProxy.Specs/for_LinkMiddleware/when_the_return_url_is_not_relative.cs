// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.for_LinkMiddleware;

public class when_the_return_url_is_not_relative : given.a_link_page_context
{
    void Establish()
    {
        _context.Request.Path = $"{WellKnownPaths.Link}/github";
        PostForm(new Dictionary<string, string>
        {
            ["returnUrl"] = "https://evil.example.com/steal",
            ["token"] = "the-link-token",
        });
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_fall_back_to_the_completion_page() =>
        _authenticationService.Received(1).ChallengeAsync(
            _context,
            "github",
            Arg.Is<AuthenticationProperties>(properties => properties.RedirectUri == WellKnownPaths.LinkComplete));
}
