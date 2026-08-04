// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.for_LinkMiddleware;

public class when_the_return_url_is_not_relative : Specification
{
    LinkMiddleware _middleware;
    DefaultHttpContext _context;
    IAuthenticationService _authenticationService;

    void Establish()
    {
        var authConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfig.CurrentValue.Returns(new C.Authentication
        {
            OAuthProviders = [new C.OAuthProvider { Name = "GitHub" }],
        });

        _middleware = new LinkMiddleware(
            _ => Task.CompletedTask,
            authConfig,
            Substitute.For<ILogger<LinkMiddleware>>());

        _context = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity("test")),
        };
        _context.Request.Path = $"{WellKnownPaths.Link}/github";
        _context.Request.QueryString = QueryString.Create(new Dictionary<string, string?>
        {
            ["returnUrl"] = "https://evil.example.com/steal",
            ["token"] = "the-link-token",
        });

        _authenticationService = Substitute.For<IAuthenticationService>();
        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(IAuthenticationService)).Returns(_authenticationService);
        _context.RequestServices = serviceProvider;
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_fall_back_to_the_application_root() =>
        _authenticationService.Received(1).ChallengeAsync(
            _context,
            "github",
            Arg.Is<AuthenticationProperties>(properties => properties.RedirectUri == "/"));
}
