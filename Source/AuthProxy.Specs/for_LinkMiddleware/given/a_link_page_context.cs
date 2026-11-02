// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.Links;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Primitives;

namespace Cratis.AuthProxy.for_LinkMiddleware.given;

public class a_link_page_context : Specification
{
    protected const string RequestToken = "the-antiforgery-request-token";

    protected LinkMiddleware _middleware;
    protected DefaultHttpContext _context;
    protected IAuthenticationService _authenticationService;
    protected IAntiforgery _antiforgery;
    protected bool _nextCalled;

    protected virtual C.AuthProxy ProxyConfiguration => new();

    /// <summary>
    /// Gets whether the request carries a valid antiforgery cookie and token.
    /// </summary>
    protected virtual bool AntiforgeryIsValid => true;

    /// <summary>
    /// Gets whether the session cookie holds a signed-in principal.
    /// </summary>
    protected virtual bool HasSession => true;

    /// <summary>
    /// Gets the principal the session cookie holds.
    /// </summary>
    protected ClaimsPrincipal SessionPrincipal { get; } = new(new ClaimsIdentity(
        [new Claim("sub", "account-1"), new Claim(SessionClaims.ProviderScheme, "microsoft")],
        CookieAuthenticationDefaults.AuthenticationScheme));

    protected string ResponseBody() => Encoding.UTF8.GetString(((MemoryStream)_context.Response.Body).ToArray());

    /// <summary>
    /// Turns the request into a form post carrying the given fields.
    /// </summary>
    /// <param name="fields">The form fields.</param>
    protected void PostForm(IDictionary<string, string> fields)
    {
        _context.Request.Method = HttpMethods.Post;
        _context.Request.ContentType = "application/x-www-form-urlencoded";
        _context.Request.Form = new FormCollection(fields.ToDictionary(_ => _.Key, _ => new StringValues(_.Value)));
    }

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
        _context.Request.Method = HttpMethods.Get;
        _context.Request.Scheme = "https";
        _context.Request.Host = new HostString("app.cratis.studio");
        _context.Response.Body = new MemoryStream();

        var environment = Substitute.For<IWebHostEnvironment>();
        environment.ContentRootPath.Returns(AppContext.BaseDirectory);

        var proxyConfig = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        proxyConfig.CurrentValue.Returns(ProxyConfiguration);

        _authenticationService = Substitute.For<IAuthenticationService>();
        _authenticationService
            .AuthenticateAsync(Arg.Any<HttpContext>(), CookieAuthenticationDefaults.AuthenticationScheme)
            .Returns(HasSession
                ? AuthenticateResult.Success(new AuthenticationTicket(SessionPrincipal, CookieAuthenticationDefaults.AuthenticationScheme))
                : AuthenticateResult.NoResult());

        _antiforgery = Substitute.For<IAntiforgery>();
        _antiforgery.IsRequestValidAsync(Arg.Any<HttpContext>()).Returns(AntiforgeryIsValid);
        _antiforgery.GetAndStoreTokens(Arg.Any<HttpContext>())
            .Returns(new AntiforgeryTokenSet(RequestToken, "the-cookie-token", ProxyAntiforgery.FormFieldName, null));

        var errorPageProvider = new ErrorPageProvider(environment, proxyConfig);
        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(IAuthenticationService)).Returns(_authenticationService);
        serviceProvider.GetService(typeof(IAntiforgery)).Returns(_antiforgery);
        serviceProvider.GetService(typeof(IErrorPageProvider)).Returns(errorPageProvider);
        serviceProvider.GetService(typeof(IOptionsMonitor<C.AuthProxy>)).Returns(proxyConfig);
        _context.RequestServices = serviceProvider;
    }
}
