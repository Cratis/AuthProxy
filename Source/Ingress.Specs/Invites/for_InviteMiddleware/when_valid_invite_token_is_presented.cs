// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.Ingress.Invites.for_InviteMiddleware;

public class when_valid_invite_token_is_presented : Specification
{
    InviteMiddleware _middleware;
    DefaultHttpContext _context;
    bool _nextCalled;

    void Establish()
    {
        var tokenValidator = Substitute.For<IInviteTokenValidator>();
        tokenValidator.Validate(Arg.Any<string>()).Returns(true);

        var config = new IngressConfig
        {
            Invite = new InviteConfig { ExchangeUrl = "http://studio/internal/invites/exchange" }
        };
        var optionsMonitor = Substitute.For<IOptionsMonitor<IngressConfig>>();
        optionsMonitor.CurrentValue.Returns(config);

        _middleware = new InviteMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            tokenValidator,
            optionsMonitor,
            Substitute.For<IHttpClientFactory>(),
            Substitute.For<ILogger<InviteMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/invite/some-token";

        // Provide a minimal authentication service so ChallengeAsync does not throw.
        var authService = Substitute.For<Microsoft.AspNetCore.Authentication.IAuthenticationService>();
        authService
            .ChallengeAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<Microsoft.AspNetCore.Authentication.AuthenticationProperties>())
            .Returns(Task.CompletedTask);
        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(Microsoft.AspNetCore.Authentication.IAuthenticationService)).Returns(authService);
        _context.RequestServices = serviceProvider;
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
    [Fact] void should_set_invite_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain(Cookies.InviteToken);
}
