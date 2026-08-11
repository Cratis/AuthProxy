// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.for_LogoutMiddleware;

public class when_logging_out_with_additional_cookies_configured : Specification
{
    LogoutMiddleware _middleware;
    DefaultHttpContext _context;

    void Establish()
    {
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(new C.AuthProxy
        {
            Logout = new C.Logout
            {
                AdditionalCookies =
                [
                    new C.LogoutCookie { Name = "_oauth2_proxy_admin", Domain = ".cratis.studio" },
                    new C.LogoutCookie { Name = "_legacy_session" }
                ]
            }
        });

        var endSessionEndpointResolver = Substitute.For<IEndSessionEndpointResolver>();
        endSessionEndpointResolver.Resolve(Arg.Any<string?>(), Arg.Any<CancellationToken>()).Returns((string?)null);

        _middleware = new LogoutMiddleware(_ => Task.CompletedTask, config, endSessionEndpointResolver, Substitute.For<ILogger<LogoutMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Scheme = "https";
        _context.Request.Host = new HostString("app.cratis.studio");
        _context.Request.Path = WellKnownPaths.Logout;
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

    [Fact]
    void should_delete_the_domain_cookie_for_the_request_host_and_for_its_domain() =>
        _context.Response.Headers.SetCookie
            .Count(_ => _?.StartsWith("_oauth2_proxy_admin=;", StringComparison.Ordinal) == true)
            .ShouldEqual(2);

    [Fact]
    void should_scope_one_of_the_deletions_to_the_configured_domain() =>
        _context.Response.Headers.SetCookie.ToString().ShouldContain("domain=.cratis.studio");

    [Fact]
    void should_delete_the_host_only_cookie_once() =>
        _context.Response.Headers.SetCookie
            .Count(_ => _?.StartsWith("_legacy_session=;", StringComparison.Ordinal) == true)
            .ShouldEqual(1);
}
