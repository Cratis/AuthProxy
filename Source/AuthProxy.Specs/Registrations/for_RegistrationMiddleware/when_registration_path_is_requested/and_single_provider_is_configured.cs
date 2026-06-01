// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Registrations.for_RegistrationMiddleware.when_registration_path_is_requested;

public class and_single_provider_is_configured : Specification
{
    RegistrationMiddleware _middleware;
    DefaultHttpContext _context;
    string _challengedScheme = string.Empty;

    void Establish()
    {
        var proxyConfig = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        proxyConfig.CurrentValue.Returns(new C.AuthProxy
        {
            Invite = new C.Invite
            {
                Lobby = new C.Service
                {
                    Registration = new C.ServiceEndpoint { BaseUrl = "http://lobby.example.com/register" }
                }
            }
        });

        var authConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfig.CurrentValue.Returns(new C.Authentication
        {
            OidcProviders = [new C.OidcProvider { Name = "provider1", Authority = "https://auth.example.com", ClientId = "id" }]
        });

        _middleware = new RegistrationMiddleware(
            _ => Task.CompletedTask,
            proxyConfig,
            authConfig,
            Substitute.For<ITenantResolver>());

        _context = new DefaultHttpContext();
        _context.Request.Path = WellKnownPaths.Registration;
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

    [Fact] void should_challenge_with_provider_scheme() => _challengedScheme.ShouldEqual(OidcProviderScheme.FromName("provider1"));
    [Fact] void should_set_registration_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain(Cookies.Registration);
}
