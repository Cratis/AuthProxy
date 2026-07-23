// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.for_LogoutMiddleware;

public class when_logging_out_with_an_oauth_session : Specification
{
    LogoutMiddleware _middleware;
    DefaultHttpContext _context;
    IAuthenticationService _authenticationService;
    IEndSessionEndpointResolver _endSessionEndpointResolver;

    void Establish()
    {
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(new C.AuthProxy());

        // An OAuth 2.0 provider (such as GitHub) has no standard OIDC end-session endpoint, so the resolver
        // returns null and the middleware must fall back to a local-only logout instead of redirecting.
        _endSessionEndpointResolver = Substitute.For<IEndSessionEndpointResolver>();
        _endSessionEndpointResolver.Resolve(Arg.Any<string?>(), Arg.Any<CancellationToken>()).Returns((string?)null);

        _middleware = new LogoutMiddleware(_ => Task.CompletedTask, config, _endSessionEndpointResolver, Substitute.For<ILogger<LogoutMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Scheme = "https";
        _context.Request.Host = new HostString("cratis.studio");
        _context.Request.Path = WellKnownPaths.Logout;
        _context.Request.QueryString = QueryString.Create("redirect", "https://cratis.studio");
        _context.Response.Body = new MemoryStream();

        var properties = new AuthenticationProperties();
        properties.Items[AuthenticationServiceCollectionExtensions.AuthenticationSchemeStateKey] = "github";
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity("test")), properties, CookieAuthenticationDefaults.AuthenticationScheme);

        _authenticationService = Substitute.For<IAuthenticationService>();
        _authenticationService.AuthenticateAsync(Arg.Any<HttpContext>(), CookieAuthenticationDefaults.AuthenticationScheme)
            .Returns(AuthenticateResult.Success(ticket));

        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(IAuthenticationService)).Returns(_authenticationService);
        _context.RequestServices = serviceProvider;
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_respond_with_found() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status302Found);
    [Fact] void should_redirect_straight_to_the_final_target() => _context.Response.Headers.Location.ToString().ShouldEqual("https://cratis.studio");
    [Fact] void should_not_carry_a_logout_redirect_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldNotContain(Cookies.LogoutRedirect);
    [Fact] void should_sign_out_of_the_authentication_cookie() => _authenticationService.Received(1).SignOutAsync(_context, CookieAuthenticationDefaults.AuthenticationScheme, Arg.Any<AuthenticationProperties>());
    [Fact] void should_clear_the_identity_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.Identity}=;");
}
