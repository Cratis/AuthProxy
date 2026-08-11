// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_LinkMiddleware;

/// <summary>
/// The bare link path is the flow's embeddable front door: the provider-selection page the product frames
/// in its modal. It never challenges — the provider leg belongs in its own top-level window — and it only
/// answers a signed-in caller holding a link token, exactly like the challenge itself.
/// </summary>
public class when_requesting_the_selection_page : given.a_link_page_context
{
    protected override C.AuthProxy ProxyConfiguration => new()
    {
        Link = new C.Link { EmbedAncestors = ["self"] },
    };

    void Establish()
    {
        _context.Request.Path = WellKnownPaths.Link;
        _context.Request.QueryString = QueryString.Create("token", "the-link-token");
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_answer_with_the_selection_page() => ResponseBody().ShouldContain("Add a Sign-In Method");
    [Fact] void should_answer_ok() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status200OK);
    [Fact] void should_not_challenge() => _authenticationService.DidNotReceiveWithAnyArgs().ChallengeAsync(default!, default, default);
    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();

    [Fact] void should_allow_the_configured_ancestor_to_frame_it() =>
        _context.Response.Headers.ContentSecurityPolicy.ToString().ShouldEqual("frame-ancestors 'self'");

    [Fact] void should_not_send_x_frame_options_when_embeddable() =>
        _context.Response.Headers.XFrameOptions.ToString().ShouldBeEmpty();

    [Fact] void should_resolve_the_own_origin_as_message_target() =>
        ResponseBody().ShouldContain("https://app.cratis.studio");
}
