// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.for_LinkMiddleware;

public class when_initiating_a_link : Specification
{
    LinkMiddleware _middleware;
    DefaultHttpContext _context;
    IAuthenticationService _authenticationService;
    bool _nextCalled;

    void Establish()
    {
        var authConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfig.CurrentValue.Returns(new C.Authentication
        {
            OAuthProviders = [new C.OAuthProvider { Name = "GitHub" }],
        });

        _middleware = new LinkMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            authConfig,
            Substitute.For<ILogger<LinkMiddleware>>());

        _context = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity("test")),
        };
        _context.Request.Path = $"{WellKnownPaths.Link}/github";
        _context.Request.QueryString = QueryString.Create(new Dictionary<string, string?>
        {
            ["returnUrl"] = "/settings/link-complete",
            ["token"] = "the-link-token",
        });

        _authenticationService = Substitute.For<IAuthenticationService>();
        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(IAuthenticationService)).Returns(_authenticationService);
        _context.RequestServices = serviceProvider;
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

    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
}
