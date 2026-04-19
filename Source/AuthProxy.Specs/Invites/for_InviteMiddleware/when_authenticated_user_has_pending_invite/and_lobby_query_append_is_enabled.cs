// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_authenticated_user_has_pending_invite;

public class and_lobby_query_append_is_enabled : Specification
{
    const string LobbyUrl = "http://lobby-service/";
    const string InvitationId = "7cf1cec4-3fdf-4dc1-9b0c-04d42d928f6e";

    InviteMiddleware _middleware;
    DefaultHttpContext _context;

    void Establish()
    {
        var tokenValidator = Substitute.For<IInviteTokenValidator>();
        tokenValidator.TryGetClaim("pending-invite-token", "jti", out Arg.Any<string>())
            .Returns(callInfo =>
            {
                callInfo[2] = InvitationId;
                return true;
            });

        var config = new C.AuthProxy
        {
            Invite = new C.Invite
            {
                ExchangeUrl = "http://studio/internal/invites/exchange",
                Lobby = new C.Service
                {
                    Frontend = new C.ServiceEndpoint { BaseUrl = LobbyUrl }
                },
                AppendInvitationIdToQueryString = true,
                InvitationIdQueryStringKey = "inviteId"
            }
        };

        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(Arg.Any<string>()).Returns(
            new HttpClient(new FakeHttpMessageHandler(HttpStatusCode.OK)));

        _middleware = new InviteMiddleware(
            _ => Task.CompletedTask,
            tokenValidator,
            optionsMonitor,
            CreateEmptyAuthConfig(),
            httpClientFactory,
            Substitute.For<IErrorPageProvider>(),
            Substitute.For<ILogger<InviteMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/";

        var identity = new ClaimsIdentity([new Claim("sub", "user-123")], "aad");
        _context.User = new ClaimsPrincipal(identity);

        _context.Request.Headers.Cookie = $"{Cookies.InviteToken}=pending-invite-token";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact]
    void should_set_lobby_redirect_url_with_configured_query_key() =>
        _context.Items[InviteMiddleware.LobbyRedirectUrlItemKey].ShouldEqual($"{LobbyUrl}?inviteId={InvitationId}");

    static IOptionsMonitor<C.Authentication> CreateEmptyAuthConfig()
    {
        var monitor = Substitute.For<IOptionsMonitor<C.Authentication>>();
        monitor.CurrentValue.Returns(new C.Authentication());
        return monitor;
    }
}
