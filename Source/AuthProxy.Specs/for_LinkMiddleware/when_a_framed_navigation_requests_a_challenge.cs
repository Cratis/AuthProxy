// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_LinkMiddleware;

/// <summary>
/// A challenge honored inside a frame redirects the frame to the external identity provider, whose pages
/// refuse to render framed — leaving a dead iframe. A framed navigation to a provider's link path is
/// answered with the selection page instead, which opens the provider leg in its own top-level window.
/// </summary>
public class when_a_framed_navigation_requests_a_challenge : given.a_link_page_context
{
    protected override C.AuthProxy ProxyConfiguration => new()
    {
        Link = new C.Link { EmbedAncestors = ["self"] },
    };

    void Establish()
    {
        _context.Request.Path = $"{WellKnownPaths.Link}/github";
        _context.Request.QueryString = QueryString.Create("token", "the-link-token");
        _context.Request.Headers["Sec-Fetch-Dest"] = "iframe";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_challenge() => _authenticationService.DidNotReceiveWithAnyArgs().ChallengeAsync(default!, default, default);
    [Fact] void should_answer_with_the_selection_page() => ResponseBody().ShouldContain("Add a Sign-In Method");
    [Fact] void should_answer_ok() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status200OK);
}
