// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.for_LogoutMiddleware;

public class when_logging_out_with_a_disallowed_redirect : Specification
{
    LogoutMiddleware _middleware;
    DefaultHttpContext _context;
    IAuthenticationService _authenticationService;

    void Establish()
    {
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(new C.AuthProxy());

        _middleware = new LogoutMiddleware(_ => Task.CompletedTask, config, Substitute.For<IEndSessionEndpointResolver>(), Substitute.For<ILogger<LogoutMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Scheme = "https";
        _context.Request.Host = new HostString("cratis.studio");
        _context.Request.Path = WellKnownPaths.Logout;
        _context.Request.QueryString = QueryString.Create("redirect", "https://evil.example.com/steal");
        _context.Response.Body = new MemoryStream();

        _authenticationService = Substitute.For<IAuthenticationService>();
        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(IAuthenticationService)).Returns(_authenticationService);
        _context.RequestServices = serviceProvider;
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_still_sign_the_user_out() => _authenticationService.Received(1).SignOutAsync(_context, Arg.Any<string>(), Arg.Any<AuthenticationProperties>());
    [Fact] void should_still_clear_the_session_cookies() => _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.Identity}=;");
    [Fact] void should_fall_back_to_the_application_root() => _context.Response.Headers.Location.ToString().ShouldEqual("/");
    [Fact] void should_respond_with_found() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status302Found);
}
