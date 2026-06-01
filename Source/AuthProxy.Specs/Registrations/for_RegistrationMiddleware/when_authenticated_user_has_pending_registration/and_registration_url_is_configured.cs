// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Registrations.for_RegistrationMiddleware.when_authenticated_user_has_pending_registration;

public class and_registration_url_is_configured : Specification
{
    const string RegistrationUrl = "http://lobby.example.com/register";

    RegistrationMiddleware _middleware;
    DefaultHttpContext _context;
    bool _nextCalled;

    void Establish()
    {
        var proxyConfig = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        proxyConfig.CurrentValue.Returns(new C.AuthProxy
        {
            Invite = new C.Invite
            {
                Lobby = new C.Service
                {
                    Registration = new C.ServiceEndpoint { BaseUrl = RegistrationUrl }
                }
            }
        });

        var authConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfig.CurrentValue.Returns(new C.Authentication());

        _middleware = new RegistrationMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            proxyConfig,
            authConfig,
            Substitute.For<ITenantResolver>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/";
        _context.Request.Headers.Cookie = $"{Cookies.Registration}=pending";
        _context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-123")], "aad"));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_call_next() => _nextCalled.ShouldBeTrue();
    [Fact] void should_set_lobby_redirect_url_in_context_items() => _context.Items[InviteMiddleware.LobbyRedirectUrlItemKey].ShouldEqual(RegistrationUrl);
    [Fact] void should_delete_registration_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain(Cookies.Registration);
}
