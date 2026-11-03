// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.for_LinkMiddleware;

public class when_initiating_a_link : given.a_link_page_context
{
    void Establish()
    {
        _context.Request.Path = $"{WellKnownPaths.Link}/github";
        PostForm(new Dictionary<string, string>
        {
            ["returnUrl"] = "/settings/link-complete",
            ["token"] = "the-link-token",
        });
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_challenge_the_requested_scheme() =>
        _authenticationService.Received(1).ChallengeAsync(_context, "github", Arg.Any<AuthenticationProperties>());

    [Fact] void should_mark_the_challenge_as_link_mode() =>
        _authenticationService.Received(1).ChallengeAsync(
            _context,
            "github",
            Arg.Is<AuthenticationProperties>(properties => properties.Items[LinkMiddleware.LinkModePropertyKey] == "true"));

    [Fact] void should_carry_the_link_token_on_the_challenge() =>
        _authenticationService.Received(1).ChallengeAsync(
            _context,
            "github",
            Arg.Is<AuthenticationProperties>(properties => properties.Items[LinkMiddleware.LinkTokenPropertyKey] == "the-link-token"));

    [Fact] void should_return_to_the_requested_relative_url() =>
        _authenticationService.Received(1).ChallengeAsync(
            _context,
            "github",
            Arg.Is<AuthenticationProperties>(properties => properties.RedirectUri == "/settings/link-complete"));

    [Fact] void should_record_the_session_binding()
    {
        LinkSessionBinding.TryCreate(SessionPrincipal, out var expected).ShouldBeTrue();
        _authenticationService.Received(1).ChallengeAsync(
            _context,
            "github",
            Arg.Is<AuthenticationProperties>(properties => properties.Items[LinkMiddleware.LinkSessionBindingPropertyKey] == expected));
    }

    [Fact] void should_record_the_selected_provider() =>
        _authenticationService.Received(1).ChallengeAsync(
            _context,
            "github",
            Arg.Is<AuthenticationProperties>(properties => properties.Items[LinkMiddleware.LinkSchemePropertyKey] == "github"));

    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
}
