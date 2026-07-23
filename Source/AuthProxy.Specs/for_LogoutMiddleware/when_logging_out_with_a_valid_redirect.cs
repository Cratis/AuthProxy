// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.for_LogoutMiddleware;

public class when_logging_out_with_a_valid_redirect : Specification
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
            config);

        _context = new DefaultHttpContext();
        _context.Request.Scheme = "https";
        _context.Request.Host = new HostString("cratis.studio");
        _context.Request.Path = WellKnownPaths.Logout;
        _context.Request.QueryString = QueryString.Create("redirect", "https://cratis.studio");
        _context.Response.Body = new MemoryStream();

        _authenticationService = Substitute.For<IAuthenticationService>();
        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(IAuthenticationService)).Returns(_authenticationService);
        _context.RequestServices = serviceProvider;
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_sign_out_of_the_authentication_cookie() => _authenticationService.Received(1).SignOutAsync(_context, CookieAuthenticationDefaults.AuthenticationScheme, Arg.Any<AuthenticationProperties>());
    [Fact] void should_clear_the_identity_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.Identity}=;");
    [Fact] void should_clear_the_selected_tenant_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.Tenant}=;");
    [Fact] void should_clear_the_tenant_list_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.Tenants}=;");
    [Fact] void should_clear_the_invite_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.InviteToken}=;");
    [Fact] void should_clear_the_registration_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.Registration}=;");
    [Fact] void should_clear_the_providers_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.Providers}=;");
    [Fact] void should_redirect_to_the_requested_target() => _context.Response.Headers.Location.ToString().ShouldEqual("https://cratis.studio");
    [Fact] void should_respond_with_found() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status302Found);
    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
}
