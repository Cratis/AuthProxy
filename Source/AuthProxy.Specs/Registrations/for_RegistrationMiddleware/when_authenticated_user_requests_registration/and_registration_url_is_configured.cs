// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Registrations.for_RegistrationMiddleware.when_authenticated_user_requests_registration;

public class and_registration_url_is_configured : Specification
{
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
                    Registration = new C.ServiceEndpoint { BaseUrl = "https://lobby.example.com/register" }
                }
            }
        });

        var authConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfig.CurrentValue.Returns(new C.Authentication
        {
            OidcProviders = [new C.OidcProvider { Name = "provider1", Authority = "https://auth.example.com", ClientId = "id" }]
        });

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
        _context.Request.Path = WellKnownPaths.Registration;
        _context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-123")], "aad"));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_let_the_request_through_to_the_lobby() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_start_another_registration() => _context.Response.Headers.SetCookie.ToString().ShouldNotContain(Cookies.Registration);
}
