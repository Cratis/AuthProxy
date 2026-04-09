// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.Ingress.Invites.for_InviteMiddleware;

public class when_authenticated_user_has_pending_invite_and_lobby_is_configured : Specification
{
    const string LobbyUrl = "http://lobby-service/";

    InviteMiddleware _middleware;
    DefaultHttpContext _context;
    bool _nextCalled;

    void Establish()
    {
        var tokenValidator = Substitute.For<IInviteTokenValidator>();

        var config = new IngressConfig
        {
            Invite = new InviteConfig
            {
                ExchangeUrl = "http://studio/internal/invites/exchange",
                Lobby = new MicroserviceConfig
                {
                    Frontend = new MicroserviceEndpointConfig { BaseUrl = LobbyUrl }
                }
            }
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
            CreateEmptyAuthConfig(),
            httpClientFactory,
            Substitute.For<IErrorPageProvider>(),
            Substitute.For<ILogger<InviteMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/";

        var identity = new System.Security.Claims.ClaimsIdentity(
            [new System.Security.Claims.Claim("sub", "user-123")], "aad");
        _context.User = new System.Security.Claims.ClaimsPrincipal(identity);

        _context.Request.Headers.Cookie = $"{Cookies.InviteToken}=pending-invite-token";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
    [Fact] void should_redirect_to_lobby() => _context.Response.Headers.Location.ToString().ShouldEqual(LobbyUrl);
    [Fact] void should_delete_invite_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain(Cookies.InviteToken);

    static IOptionsMonitor<AuthenticationConfig> CreateEmptyAuthConfig()
    {
        var monitor = Substitute.For<IOptionsMonitor<AuthenticationConfig>>();
        monitor.CurrentValue.Returns(new AuthenticationConfig());
        return monitor;
    }
}
