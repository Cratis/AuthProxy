// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_LinkMiddleware;

/// <summary>
/// Embedding is opt-in per deployment: until an allowed ancestor origin is configured, the link pages
/// refuse to be framed at all — the proxy never opens itself to framing by default.
/// </summary>
public class when_requesting_the_selection_page_without_embedding_configured : given.a_link_page_context
{
    void Establish()
    {
        _context.Request.Path = WellKnownPaths.Link;
        _context.Request.QueryString = QueryString.Create("token", "the-link-token");
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_forbid_framing_through_content_security_policy() =>
        _context.Response.Headers.ContentSecurityPolicy.ToString().ShouldEqual("frame-ancestors 'none'");

    [Fact] void should_forbid_framing_through_x_frame_options() =>
        _context.Response.Headers.XFrameOptions.ToString().ShouldEqual("DENY");
}
