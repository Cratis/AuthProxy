// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_SelectProviderMiddleware.when_request_is_for_the_selection_page_itself;

/// <summary>
/// A request landing directly on <c>/.cratis/select-provider</c> — the way the cookie authentication
/// handler's redirect and the invite flow both send an unauthenticated caller there — must be answered
/// by this middleware itself, not deferred to a later handler. Regression coverage: this path used to be
/// treated as already-authentication-UI and skipped via <c>next()</c>, landing on a separate, unbranded
/// page instead of the one this middleware serves for every other unauthenticated request.
/// </summary>
public class and_multiple_providers_are_configured : Specification
{
    SelectProviderMiddleware _middleware;
    DefaultHttpContext _context;
    bool _nextCalled;
    IErrorPageProvider _errorPageProvider;

    void Establish()
    {
        var authConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfig.CurrentValue.Returns(new C.Authentication
        {
            OidcProviders =
            [
                new C.OidcProvider { Name = "Provider One", Authority = "https://a.example.com", ClientId = "c1" },
                new C.OidcProvider { Name = "Provider Two", Authority = "https://b.example.com", ClientId = "c2" }
            ]
        });

        _errorPageProvider = Substitute.For<IErrorPageProvider>();
        _errorPageProvider
            .WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>())
            .Returns(Task.CompletedTask);

        var proxyConfig = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        proxyConfig.CurrentValue.Returns(new C.AuthProxy());

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
        _context.Request.QueryString = new QueryString("?returnUrl=%2Finvite%2Fabc123");
        _context.Request.Headers["Sec-Fetch-Dest"] = "document";
        _context.Response.Body = new System.IO.MemoryStream();
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();

    [Fact]
    void should_serve_select_provider_page() =>
        _errorPageProvider.Received(1).WriteErrorPageAsync(
            _context,
            WellKnownPageNames.SelectProvider,
            StatusCodes.Status200OK);
}
