// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.for_LinkMiddleware;

public class when_the_provider_is_not_configured : Specification
{
    LinkMiddleware _middleware;
    DefaultHttpContext _context;
    IAuthenticationService _authenticationService;
    bool _nextCalled;

    void Establish()
    {
        var authConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfig.CurrentValue.Returns(new C.Authentication());

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
        _context.Request.Path = $"{WellKnownPaths.Link}/unknown";
        _context.Request.QueryString = QueryString.Create("token", "the-link-token");

        _authenticationService = Substitute.For<IAuthenticationService>();
        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(IAuthenticationService)).Returns(_authenticationService);
        _context.RequestServices = serviceProvider;
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_respond_with_not_found() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status404NotFound);
    [Fact] void should_not_challenge() => _authenticationService.DidNotReceive().ChallengeAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<AuthenticationProperties>());
    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
}
