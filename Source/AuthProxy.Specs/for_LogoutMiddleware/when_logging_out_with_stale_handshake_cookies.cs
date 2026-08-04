// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.for_LogoutMiddleware;

public class when_logging_out_with_stale_handshake_cookies : Specification
{
    LogoutMiddleware _middleware;
    DefaultHttpContext _context;

    void Establish()
    {
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(new C.AuthProxy());

        var endSessionEndpointResolver = Substitute.For<IEndSessionEndpointResolver>();
        endSessionEndpointResolver.Resolve(Arg.Any<string?>(), Arg.Any<CancellationToken>()).Returns((string?)null);

        _middleware = new LogoutMiddleware(_ => Task.CompletedTask, config, endSessionEndpointResolver, Substitute.For<ILogger<LogoutMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Scheme = "https";
        _context.Request.Host = new HostString("cratis.studio");
        _context.Request.Path = WellKnownPaths.Logout;

        // Two correlation cookies and a nonce cookie left behind by abandoned sign-in handshakes, alongside an
        // unrelated cookie that must be preserved.
        _context.Request.Headers.Cookie =
            $"{Cookies.CorrelationPrefix}github.abc=one; {Cookies.CorrelationPrefix}xyz=two; {Cookies.NoncePrefix}def=three; keep-me=value";
        _context.Response.Body = new MemoryStream();

        var properties = new AuthenticationProperties();
        properties.Items[AuthenticationServiceCollectionExtensions.AuthenticationSchemeStateKey] = "github";
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity("test")), properties, CookieAuthenticationDefaults.AuthenticationScheme);

        var authenticationService = Substitute.For<IAuthenticationService>();
        authenticationService.AuthenticateAsync(Arg.Any<HttpContext>(), CookieAuthenticationDefaults.AuthenticationScheme)
            .Returns(AuthenticateResult.Success(ticket));

        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(IAuthenticationService)).Returns(authenticationService);
        _context.RequestServices = serviceProvider;
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_clear_the_first_correlation_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.CorrelationPrefix}github.abc=;");
    [Fact] void should_clear_the_second_correlation_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.CorrelationPrefix}xyz=;");
    [Fact] void should_clear_the_nonce_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.NoncePrefix}def=;");
    [Fact] void should_not_clear_unrelated_cookies() => _context.Response.Headers.SetCookie.ToString().ShouldNotContain("keep-me=;");
}
