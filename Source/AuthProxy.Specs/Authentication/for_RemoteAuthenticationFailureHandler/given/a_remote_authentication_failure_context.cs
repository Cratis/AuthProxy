// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace Cratis.AuthProxy.Authentication.for_RemoteAuthenticationFailureHandler.given;

public class a_remote_authentication_failure_context : Specification
{
    protected DefaultHttpContext _context;
    protected AuthenticationScheme _scheme;
    protected RemoteAuthenticationOptions _options;

    void Establish()
    {
        _context = new DefaultHttpContext();
        _context.Request.Scheme = "https";
        _context.Request.Host = new HostString("cratis.studio");
        _context.Request.Path = "/signin-microsoft";
        _context.Response.Body = new MemoryStream();

        var loggerFactory = Substitute.For<ILoggerFactory>();
        loggerFactory.CreateLogger(Arg.Any<string>()).Returns(Substitute.For<ILogger>());
        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(ILoggerFactory)).Returns(loggerFactory);
        _context.RequestServices = serviceProvider;

        _scheme = new AuthenticationScheme("microsoft", "microsoft", typeof(OpenIdConnectHandler));
        _options = new RemoteAuthenticationOptions();
    }
}
