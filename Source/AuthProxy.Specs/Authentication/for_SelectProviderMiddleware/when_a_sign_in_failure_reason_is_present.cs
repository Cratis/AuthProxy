// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_SelectProviderMiddleware;

public class when_a_sign_in_failure_reason_is_present : Specification
{
    SelectProviderMiddleware _middleware;
    DefaultHttpContext _context;
    bool _nextCalled;
    bool _challenged;
    IErrorPageProvider _errorPageProvider;

    void Establish()
    {
        var proxyConfig = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        proxyConfig.CurrentValue.Returns(new C.AuthProxy());

        // A single provider would normally be challenged directly — but this caller just came back from a
        // failed sign-in, and an immediate re-challenge is a redirect loop when the failure persists.
        var authConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfig.CurrentValue.Returns(new C.Authentication
        {
            OidcProviders = [new C.OidcProvider { Name = "my-provider", Authority = "https://auth.example.com", ClientId = "id" }]
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
            Substitute.For<ITenantResolver>(),
            Substitute.For<IAuthenticationSchemeProvider>());

        _context = new DefaultHttpContext();
        _context.Request.Path = WellKnownPaths.LoginPage;
        _context.Request.QueryString = new QueryString($"?{SignInFailureReason.QueryKey}={SignInFailureReason.RemoteFailure}&returnUrl=%2Fdashboard");
        _context.Request.Headers["Sec-Fetch-Dest"] = "document";
        _context.Response.Body = new MemoryStream();

        var authService = Substitute.For<IAuthenticationService>();
        authService
            .ChallengeAsync(Arg.Any<HttpContext>(), Arg.Do<string?>(_ => _challenged = true), Arg.Any<AuthenticationProperties?>())
            .Returns(Task.CompletedTask);

        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(IAuthenticationService)).Returns(authService);
        _context.RequestServices = serviceProvider;
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
    [Fact] void should_not_challenge_the_provider() => _challenged.ShouldBeFalse();

    [Fact]
    void should_serve_the_selection_page() =>
        _errorPageProvider.Received(1).WriteErrorPageAsync(
            _context,
            WellKnownPageNames.SelectProvider,
            StatusCodes.Status200OK);

    [Fact]
    void should_set_the_providers_cookie() =>
        _context.Response.Headers.SetCookie.ToString().ShouldContain(Cookies.Providers);
}
