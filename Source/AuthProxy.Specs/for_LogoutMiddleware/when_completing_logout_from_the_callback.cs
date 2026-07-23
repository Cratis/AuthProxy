// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.for_LogoutMiddleware;

public class when_completing_logout_from_the_callback : Specification
{
    LogoutMiddleware _middleware;
    DefaultHttpContext _context;
    IAuthenticationService _authenticationService;
    bool _nextCalled;

    void Establish()
    {
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(new C.AuthProxy());

        _middleware = new LogoutMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            config,
            Substitute.For<IEndSessionEndpointResolver>(),
            Substitute.For<ILogger<LogoutMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Scheme = "https";
        _context.Request.Host = new HostString("cratis.studio");
        _context.Request.Path = WellKnownPaths.LogoutCallback;

        // The identity provider redirects back to the callback carrying the validated final target in the
        // proxy-set logout cookie.
        _context.Request.Headers.Cookie = $"{Cookies.LogoutRedirect}=https://cratis.studio";
        _context.Response.Body = new MemoryStream();

        _authenticationService = Substitute.For<IAuthenticationService>();
        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(IAuthenticationService)).Returns(_authenticationService);
        _context.RequestServices = serviceProvider;
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_respond_with_found() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status302Found);
    [Fact] void should_redirect_to_the_carried_target() => _context.Response.Headers.Location.ToString().ShouldEqual("https://cratis.studio");
    [Fact] void should_sign_out_of_the_authentication_cookie() => _authenticationService.Received(1).SignOutAsync(_context, CookieAuthenticationDefaults.AuthenticationScheme, Arg.Any<AuthenticationProperties>());
    [Fact] void should_clear_the_identity_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.Identity}=;");
    [Fact] void should_clear_the_selected_tenant_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.Tenant}=;");
    [Fact] void should_clear_the_logout_redirect_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.LogoutRedirect}=;");
    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
}
