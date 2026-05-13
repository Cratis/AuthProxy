// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SelectProviderMiddleware.when_lobby_mode_is_configured.given;

public class lobby_mode_middleware : Specification
{
    protected const string LobbyUrl = "http://lobby.example.com/";

    protected SelectProviderMiddleware _middleware;
    protected DefaultHttpContext _context;
    protected bool _nextCalled;
    protected IErrorPageProvider _errorPageProvider;

    void Establish()
    {
        var proxyConfig = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        proxyConfig.CurrentValue.Returns(new C.AuthProxy
        {
            Invite = new C.Invite
            {
                RedirectToLobbyWhenTenantUnresolved = true,
                Lobby = new C.Service
                {
                    Frontend = new C.ServiceEndpoint { BaseUrl = LobbyUrl }
                }
            }
        });

        var authConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfig.CurrentValue.Returns(new C.Authentication
        {
            OidcProviders = [new C.OidcProvider { Name = "provider1", Authority = "https://auth.example.com", ClientId = "id" }]
        });

        _errorPageProvider = Substitute.For<IErrorPageProvider>();
        _errorPageProvider
            .WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>())
            .Returns(Task.CompletedTask);

        _middleware = new SelectProviderMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            proxyConfig,
            authConfig,
            _errorPageProvider,
            Substitute.For<ITenantResolver>());

        _context = new DefaultHttpContext();
        _context.Response.Body = new System.IO.MemoryStream();
    }
}
