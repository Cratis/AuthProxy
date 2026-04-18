// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

public class when_no_provider_is_configured : Specification
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
        authConfigMonitor.CurrentValue.Returns(new C.Authentication());

        var httpContext = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection()
                .AddSingleton(authConfigMonitor)
                .BuildServiceProvider()
        };
        httpContext.Response.Body = new MemoryStream();

        _redirectContext = new RedirectContext<CookieAuthenticationOptions>(
            httpContext,
            new AuthenticationScheme(CookieAuthenticationDefaults.AuthenticationScheme, null, typeof(IAuthenticationHandler)),
            cookieOptions,
            new AuthenticationProperties(),
            "/.cratis/login");
    }

    Task Because() => _redirectContext.Options.Events.OnRedirectToLogin(_redirectContext);

    [Fact] void should_return_500() => _redirectContext.Response.StatusCode.ShouldEqual(StatusCodes.Status500InternalServerError);

    [Fact]
    void should_write_configuration_guidance_message()
    {
        _redirectContext.Response.Body.Position = 0;
        using var reader = new StreamReader(_redirectContext.Response.Body);
        var body = reader.ReadToEnd();
        body.ShouldContain("Authentication is not configured");
    }
}
