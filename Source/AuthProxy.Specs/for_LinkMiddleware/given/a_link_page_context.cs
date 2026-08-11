// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Cratis.AuthProxy.Links;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;

namespace Cratis.AuthProxy.for_LinkMiddleware.given;

public class a_link_page_context : Specification
{
    protected LinkMiddleware _middleware;
    protected DefaultHttpContext _context;
    protected IAuthenticationService _authenticationService;
    protected bool _nextCalled;

    protected virtual C.AuthProxy ProxyConfiguration => new();

    protected string ResponseBody() => Encoding.UTF8.GetString(((MemoryStream)_context.Response.Body).ToArray());

    void Establish()
    {
        var authConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfig.CurrentValue.Returns(new C.Authentication
        {
            OAuthProviders = [new C.OAuthProvider { Name = "GitHub" }],
        });

        _middleware = new LinkMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            authConfig,
            Substitute.For<ILogger<LinkMiddleware>>());

        _context = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity("test")),
        };
        _context.Request.Scheme = "https";
        _context.Request.Host = new HostString("app.cratis.studio");
        _context.Response.Body = new MemoryStream();

        var environment = Substitute.For<IWebHostEnvironment>();
        environment.ContentRootPath.Returns(AppContext.BaseDirectory);

        var proxyConfig = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        proxyConfig.CurrentValue.Returns(ProxyConfiguration);

        _authenticationService = Substitute.For<IAuthenticationService>();
        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(IAuthenticationService)).Returns(_authenticationService);
        serviceProvider.GetService(typeof(IErrorPageProvider)).Returns(new ErrorPageProvider(environment, proxyConfig));
        serviceProvider.GetService(typeof(IOptionsMonitor<C.AuthProxy>)).Returns(proxyConfig);
        _context.RequestServices = serviceProvider;
    }
}
