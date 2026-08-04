// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.for_LinkMiddleware;

public class when_the_user_is_not_authenticated : Specification
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

        // No authentication ticket - an anonymous ClaimsIdentity is not authenticated.
        _context = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity()),
        };
        _context.Request.Path = $"{WellKnownPaths.Link}/github";
        _context.Request.QueryString = QueryString.Create("token", "the-link-token");

        _authenticationService = Substitute.For<IAuthenticationService>();
        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(IAuthenticationService)).Returns(_authenticationService);
        _context.RequestServices = serviceProvider;
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_respond_with_unauthorized() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);
    [Fact] void should_not_challenge() => _authenticationService.DidNotReceive().ChallengeAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<AuthenticationProperties>());
    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
}
