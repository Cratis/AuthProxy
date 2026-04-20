// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_SelectProviderMiddleware;

public class when_single_provider_is_configured : Specification
{
    SelectProviderMiddleware _middleware;
    DefaultHttpContext _context;
    bool _nextCalled;
    string _challengedScheme = string.Empty;

    void Establish()
    {
        var authConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfig.CurrentValue.Returns(new C.Authentication
        {
            OidcProviders = [new C.OidcProvider { Name = "my-provider", Authority = "https://auth.example.com", ClientId = "id" }]
        });

        _middleware = new SelectProviderMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            authConfig,
            Substitute.For<IErrorPageProvider>(),
            Substitute.For<ITenantResolver>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/protected";
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

    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
    [Fact] void should_challenge_with_provider_scheme() => _challengedScheme.ShouldEqual(OidcProviderScheme.FromName("my-provider"));
}
