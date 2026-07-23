// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.for_LogoutMiddleware;

public class when_logging_out_without_a_redirect : Specification
{
    LogoutMiddleware _middleware;
    DefaultHttpContext _context;

    void Establish()
    {
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(new C.AuthProxy());

        _middleware = new LogoutMiddleware(_ => Task.CompletedTask, config);

        _context = new DefaultHttpContext();
        _context.Request.Scheme = "https";
        _context.Request.Host = new HostString("cratis.studio");
        _context.Request.Path = WellKnownPaths.Logout;
        _context.Response.Body = new MemoryStream();

        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(IAuthenticationService)).Returns(Substitute.For<IAuthenticationService>());
        _context.RequestServices = serviceProvider;
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_fall_back_to_the_application_root() => _context.Response.Headers.Location.ToString().ShouldEqual("/");
    [Fact] void should_respond_with_found() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status302Found);
    [Fact] void should_clear_the_session_cookies() => _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.Tenant}=;");
}
