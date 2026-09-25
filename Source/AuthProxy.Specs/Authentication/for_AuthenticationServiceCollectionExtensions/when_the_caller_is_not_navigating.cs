// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// A caller that is not navigating to a document must be refused with <c language="text">401</c> when its session has
/// expired, not handed the login-selection redirect.
/// <para>
/// A browser follows that redirect and reads the resulting login page as a plain <c language="text">200</c> - the
/// conventional <c language="text">response.ok</c> check passes, and a command POST or an identity poll either misreads
/// the page as its expected JSON or never learns the session ended at all. This is what happened in
/// production: a session outlived by an idle tab expired, every subsequent command silently failed, and
/// the identity poll's own JSON parse threw instead of settling on an unauthenticated state the frontend
/// could act on.
/// </para>
/// </summary>
public class when_the_caller_is_not_navigating : Specification
{
    RedirectContext<CookieAuthenticationOptions> _redirectContext;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.AddIngressAuthentication();

        var serviceProvider = builder.Services.BuildServiceProvider();
        var cookieOptionsMonitor = serviceProvider.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>();
        var cookieOptions = cookieOptionsMonitor.Get(CookieAuthenticationDefaults.AuthenticationScheme);

        var authConfigMonitor = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfigMonitor.CurrentValue.Returns(new C.Authentication
        {
            OAuthProviders =
            [
                new C.OAuthProvider { Name = "GitHub" }
            ]
        });

        var httpContext = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection()
                .AddSingleton(authConfigMonitor)
                .BuildServiceProvider()
        };
        httpContext.Request.Path = "/api/work-items/retry";
        httpContext.Request.Headers["Sec-Fetch-Dest"] = "empty";
        httpContext.Request.Headers.Accept = "*/*";
        httpContext.Response.Body = new MemoryStream();

        _redirectContext = new RedirectContext<CookieAuthenticationOptions>(
            httpContext,
            new AuthenticationScheme(CookieAuthenticationDefaults.AuthenticationScheme, null, typeof(IAuthenticationHandler)),
            cookieOptions,
            new AuthenticationProperties(),
            "/.cratis/login");
    }

    Task Because() => _redirectContext.Options.Events.OnRedirectToLogin(_redirectContext);

    [Fact] void should_refuse_with_401() => _redirectContext.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);
    [Fact] void should_not_set_a_redirect_location() => _redirectContext.Response.Headers.Location.ToString().ShouldBeEmpty();
}
