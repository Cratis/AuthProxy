// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_SessionLifetimePolicy;

public class when_the_cookie_handler_signs_in_with_a_preset_expiry : Specification
{
    readonly given.a_session_clock _clock = new();
    ServiceProvider _services;
    AuthenticationProperties _observed;
    AuthenticationTicket _original;
    AuthenticationTicket _renewed;
    string _nonRenewableCookie;

    void Establish()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthentication().AddCookie(options =>
        {
            options.TimeProvider = _clock;
            options.ExpireTimeSpan = TimeSpan.FromHours(12);
            options.SlidingExpiration = true;
            options.Events.OnSigningIn = context =>
            {
                _observed ??= context.Properties;
                return Task.CompletedTask;
            };
        });
        _services = services.BuildServiceProvider();
    }

    async Task Because()
    {
        var cookie = await SignIn(true);
        _original = Options().TicketDataFormat.Unprotect(cookie)!;
        var nonRenewable = await SignIn(false);
        _clock.Advance(TimeSpan.FromMinutes(6));
        _renewed = Options().TicketDataFormat.Unprotect(await Authenticate(cookie))!;
        _nonRenewableCookie = await Authenticate(nonRenewable);
    }

    CookieAuthenticationOptions Options() => _services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get("Cookies");

    async Task<string> SignIn(bool allowRefresh)
    {
        await using var scope = _services.CreateAsyncScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        var properties = new AuthenticationProperties
        {
            IssuedUtc = _clock.GetUtcNow(),
            ExpiresUtc = _clock.GetUtcNow().AddMinutes(10),
            AllowRefresh = allowRefresh
        };
        await context.SignInAsync("Cookies", new ClaimsPrincipal(new ClaimsIdentity("Cookies")), properties);
        return CookieValue(context);
    }

    async Task<string> Authenticate(string cookie)
    {
        await using var scope = _services.CreateAsyncScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Request.Headers.Cookie = $"{Options().Cookie.Name}={cookie}";
        var handler = new given.a_cookie_handler(
            _services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>(),
            _services.GetRequiredService<Microsoft.Extensions.Logging.ILoggerFactory>());
        await handler.InitializeAsync(new AuthenticationScheme("Cookies", null, typeof(CookieAuthenticationHandler)), context);
        var result = await handler.AuthenticateAsync();
        result.Succeeded.ShouldBeTrue();
        await handler.Complete();
        return CookieValue(context);
    }

    static string CookieValue(HttpContext context) => context.Response.Headers.SetCookie.ToString().Split(';')[0].Split('=', 2).ElementAtOrDefault(1) ?? string.Empty;

    void Destroy() => _services.Dispose();

    [Fact] void should_preserve_the_preset_issue_time() => _original.Properties.IssuedUtc.ShouldEqual(_observed.IssuedUtc);
    [Fact] void should_observe_the_preset_expiry_before_signing_in() => (_observed.ExpiresUtc - _observed.IssuedUtc).ShouldEqual(TimeSpan.FromMinutes(10));
    [Fact] void should_preserve_the_preset_expiry() => (_original.Properties.ExpiresUtc - _original.Properties.IssuedUtc).ShouldEqual(TimeSpan.FromMinutes(10));
    [Fact] void should_renew_with_the_original_span() => (_renewed.Properties.ExpiresUtc - _renewed.Properties.IssuedUtc).ShouldEqual(TimeSpan.FromMinutes(10));
    [Fact] void should_advance_the_renewed_issue_time() => _renewed.Properties.IssuedUtc.ShouldEqual(_original.Properties.IssuedUtc!.Value.AddMinutes(6));
    [Fact] void should_not_renew_without_permission() => _nonRenewableCookie.ShouldEqual(string.Empty);
}
