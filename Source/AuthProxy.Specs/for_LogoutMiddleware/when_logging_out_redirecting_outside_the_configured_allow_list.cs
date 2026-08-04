// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.for_LogoutMiddleware;

public class when_logging_out_redirecting_outside_the_configured_allow_list : Specification
{
    LogoutMiddleware _middleware;
    DefaultHttpContext _context;

    void Establish()
    {
        var authProxyConfig = new C.AuthProxy
        {
            Logout = new C.Logout
            {
                AllowedRedirectOrigins = ["https://cratis.studio"]
            }
        };
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(authProxyConfig);

        _middleware = new LogoutMiddleware(_ => Task.CompletedTask, config, Substitute.For<IEndSessionEndpointResolver>(), Substitute.For<ILogger<LogoutMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Scheme = "https";
        _context.Request.Host = new HostString("app.cratis.studio");
        _context.Request.Path = WellKnownPaths.Logout;
        _context.Request.QueryString = QueryString.Create("redirect", "https://evil.example.com/steal");
        _context.Response.Body = new MemoryStream();

        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(IAuthenticationService)).Returns(Substitute.For<IAuthenticationService>());
        _context.RequestServices = serviceProvider;
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_fall_back_to_the_application_root() => _context.Response.Headers.Location.ToString().ShouldEqual("/");
    [Fact] void should_respond_with_found() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status302Found);
}
