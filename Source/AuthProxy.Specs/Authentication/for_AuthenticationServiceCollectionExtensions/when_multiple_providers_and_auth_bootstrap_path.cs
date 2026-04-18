// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

public class when_multiple_providers_and_auth_bootstrap_path : Specification
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
            OidcProviders =
            [
                new C.OidcProvider { Name = "Microsoft" },
                new C.OidcProvider { Name = "GitHub" }
            ]
        });

        var httpContext = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection()
                .AddSingleton(authConfigMonitor)
                .BuildServiceProvider()
        };
        httpContext.Request.Path = WellKnownPaths.Providers;

        _redirectContext = new RedirectContext<CookieAuthenticationOptions>(
            httpContext,
            new AuthenticationScheme(CookieAuthenticationDefaults.AuthenticationScheme, null, typeof(IAuthenticationHandler)),
            cookieOptions,
            new AuthenticationProperties(),
            "/.cratis/login");
    }

    Task Because() => _redirectContext.Options.Events.OnRedirectToLogin(_redirectContext);

    [Fact] void should_redirect_to_select_provider_page_with_root_return_url() =>
        _redirectContext.Response.Headers.Location.ToString()
            .ShouldEqual("/.cratis/select-provider?returnUrl=%2F");
}
