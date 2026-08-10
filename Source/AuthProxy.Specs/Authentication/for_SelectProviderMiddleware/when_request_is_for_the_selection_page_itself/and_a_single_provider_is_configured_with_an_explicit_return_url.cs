// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_SelectProviderMiddleware.when_request_is_for_the_selection_page_itself;

/// <summary>
/// When the caller already landed on <c>/.cratis/select-provider?returnUrl=...</c> — the wrapper the
/// cookie authentication handler's redirect and the invite flow use — the real destination is the query
/// value, not the wrapper path around it. Regression coverage for a challenge that used to redirect back
/// to the wrapper URL instead of the caller's actual destination once this path stopped being skipped.
/// </summary>
public class and_a_single_provider_is_configured_with_an_explicit_return_url : Specification
{
    SelectProviderMiddleware _middleware;
    DefaultHttpContext _context;
    AuthenticationProperties _challengeProperties;

    void Establish()
    {
        var proxyConfig = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        proxyConfig.CurrentValue.Returns(new C.AuthProxy());

        var authConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfig.CurrentValue.Returns(new C.Authentication
        {
            OidcProviders = [new C.OidcProvider { Name = "my-provider", Authority = "https://auth.example.com", ClientId = "id" }]
        });

        _middleware = new SelectProviderMiddleware(
            _ => Task.CompletedTask,
            proxyConfig,
            authConfig,
            Substitute.For<IErrorPageProvider>(),
            Substitute.For<ITenantResolver>(),
            Substitute.For<IAuthenticationSchemeProvider>());

        _context = new DefaultHttpContext();
        _context.Request.Path = WellKnownPaths.LoginPage;
        _context.Request.QueryString = new QueryString("?returnUrl=%2Finvite%2Fabc123");
        _context.Request.Headers["Sec-Fetch-Dest"] = "document";
        _context.Response.Body = new System.IO.MemoryStream();

        var authService = Substitute.For<IAuthenticationService>();
        authService
            .ChallengeAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Do<AuthenticationProperties>(p => _challengeProperties = p))
            .Returns(Task.CompletedTask);

        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(IAuthenticationService)).Returns(authService);
        _context.RequestServices = serviceProvider;
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_redirect_to_the_unwrapped_return_url() => _challengeProperties.RedirectUri.ShouldEqual("/invite/abc123");
}
