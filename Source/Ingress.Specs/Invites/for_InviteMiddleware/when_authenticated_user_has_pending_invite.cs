// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.Ingress.Invites.for_InviteMiddleware;

public class when_authenticated_user_has_pending_invite : Specification
{
    InviteMiddleware _middleware;
    DefaultHttpContext _context;
    bool _nextCalled;

    void Establish()
    {
        var tokenValidator = Substitute.For<IInviteTokenValidator>();

        var config = new IngressConfig
        {
            Invite = new InviteConfig { ExchangeUrl = "http://studio/internal/invites/exchange" }
        };
        var optionsMonitor = Substitute.For<IOptionsMonitor<IngressConfig>>();
        optionsMonitor.CurrentValue.Returns(config);

        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(Arg.Any<string>()).Returns(
            new System.Net.Http.HttpClient(new FakeHttpMessageHandler(HttpStatusCode.OK)));

        _middleware = new InviteMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            tokenValidator,
            optionsMonitor,
            httpClientFactory,
            Substitute.For<IErrorPageProvider>(),
            Substitute.For<ILogger<InviteMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/";

        // Simulate authenticated user.
        var identity = new System.Security.Claims.ClaimsIdentity(
            [new System.Security.Claims.Claim("sub", "user-123")], "aad");
        _context.User = new System.Security.Claims.ClaimsPrincipal(identity);

        // Simulate pending invite cookie.
        _context.Request.Headers.Cookie = $"{Cookies.InviteToken}=pending-invite-token";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_call_next() => _nextCalled.ShouldBeTrue();
    [Fact] void should_delete_invite_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain(Cookies.InviteToken);
}
