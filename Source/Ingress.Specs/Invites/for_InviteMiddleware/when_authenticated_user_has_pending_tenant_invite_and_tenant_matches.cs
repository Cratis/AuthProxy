// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.Ingress.Invites.for_InviteMiddleware;

public class when_authenticated_user_has_pending_tenant_invite_and_tenant_matches : Specification
{
    const string LobbyUrl = "http://lobby-service/";
    const string TenantClaimType = "tenant_id";
    static readonly Guid _tenantId = Guid.NewGuid();

    InviteMiddleware _middleware;
    DefaultHttpContext _context;
    bool _nextCalled;

    void Establish()
    {
        var tokenValidator = Substitute.For<IInviteTokenValidator>();
        tokenValidator.TryGetClaim(Arg.Any<string>(), TenantClaimType, out Arg.Any<string>())
            .Returns(x =>
            {
                x[2] = _tenantId.ToString();
                return true;
            });

        var config = new IngressConfig
        {
            Invite = new InviteConfig
            {
                ExchangeUrl = "http://studio/internal/invites/exchange",
                TenantClaim = TenantClaimType,
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
            new HttpClient(new FakeHttpMessageHandler(HttpStatusCode.OK)));

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

        var identity = new ClaimsIdentity(
            [new Claim("sub", "user-123")], "aad");
        _context.User = new ClaimsPrincipal(identity);

        _context.Request.Headers.Cookie = $"{Cookies.InviteToken}=pending-invite-token";
        _context.Items[TenancyMiddleware.TenantIdItemKey] = _tenantId;
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_call_next() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_redirect_to_lobby() => _context.Response.Headers.Location.ToString().ShouldNotContain(LobbyUrl);
    [Fact] void should_delete_invite_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain(Cookies.InviteToken);

    static IOptionsMonitor<AuthenticationConfig> CreateEmptyAuthConfig()
    {
        var monitor = Substitute.For<IOptionsMonitor<AuthenticationConfig>>();
        monitor.CurrentValue.Returns(new AuthenticationConfig());
        return monitor;
    }
}
