// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_SelectProviderMiddleware.when_lobby_mode_is_configured;

public class and_lobby_url_is_not_configured : Specification
{
    SelectProviderMiddleware _middleware;
    DefaultHttpContext _context;
    string _challengedScheme = string.Empty;
    IErrorPageProvider _errorPageProvider;

    void Establish()
    {
        var proxyConfig = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        proxyConfig.CurrentValue.Returns(new C.AuthProxy
        {
            Invite = new C.Invite
            {
                RedirectToLobbyWhenTenantUnresolved = true
            }
        });

        var authConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfig.CurrentValue.Returns(new C.Authentication
        {
            OidcProviders = [new C.OidcProvider { Name = "provider1", Authority = "https://auth.example.com", ClientId = "id" }]
        });

        _errorPageProvider = Substitute.For<IErrorPageProvider>();

        _middleware = new SelectProviderMiddleware(
            _ => Task.CompletedTask,
            proxyConfig,
            authConfig,
            _errorPageProvider,
            Substitute.For<ITenantResolver>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/";
        _context.Response.Body = new System.IO.MemoryStream();

        var authService = Substitute.For<IAuthenticationService>();
        authService
            .ChallengeAsync(Arg.Any<HttpContext>(), Arg.Do<string>(s => _challengedScheme = s), Arg.Any<AuthenticationProperties>())
            .Returns(Task.CompletedTask);

        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(IAuthenticationService)).Returns(authService);
        _context.RequestServices = serviceProvider;
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_serve_invitation_required_page() =>
        _errorPageProvider.DidNotReceive().WriteErrorPageAsync(
            Arg.Any<HttpContext>(),
            WellKnownPageNames.InvitationRequired,
            Arg.Any<int>());
    [Fact] void should_challenge_with_provider_scheme() => _challengedScheme.ShouldEqual(OidcProviderScheme.FromName("provider1"));
}
