// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

public class when_applying_provider_session_lifetimes : given.configured_provider_sessions
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task should_apply_the_configured_lifetime_without_trusting_claims_or_request_input(bool oidc)
    {
        await using var services = Services("02:00:00", true);
        var properties = new AuthenticationProperties();
        properties.Items["Session:Lifetime"] = "24:00:00";
        var context = Ticket(services, oidc, properties);
        await Receive(context);
        properties.IssuedUtc.ShouldEqual(_clock.GetUtcNow());
        properties.ExpiresUtc.ShouldEqual(_clock.GetUtcNow().AddHours(2));
        properties.AllowRefresh.ShouldEqual(false);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task should_preserve_an_earlier_provider_expiry_and_issue_time(bool oidc)
    {
        await using var services = Services("02:00:00", null);
        var issued = _clock.GetUtcNow().AddMinutes(-5);
        var properties = new AuthenticationProperties { IssuedUtc = issued, ExpiresUtc = issued.AddMinutes(30) };
        await Receive(Ticket(services, oidc, properties));
        properties.IssuedUtc.ShouldEqual(issued);
        properties.ExpiresUtc.ShouldEqual(issued.AddMinutes(30));
    }

    [Theory]
    [InlineData(true, "inherit")]
    [InlineData(false, "inherit")]
    [InlineData(true, "disable-sliding")]
    [InlineData(false, "disable-sliding")]
    [InlineData(true, "shorter-sliding")]
    [InlineData(false, "shorter-sliding")]
    public async Task should_follow_the_effective_sliding_policy(bool oidc, string scenario)
    {
        var (lifetime, providerSliding, globalSliding, hours, allowRefresh) = scenario switch
        {
            "inherit" => ((string?)null, (bool?)null, false, (int?)null, (bool?)null),
            "disable-sliding" => (null, false, true, 12, false),
            "shorter-sliding" => ("02:00:00", null, true, 2, null),
            _ => throw new InvalidOperationException()
        };
        await using var services = Services(lifetime, providerSliding, globalSliding);
        var properties = new AuthenticationProperties();
        await Receive(Ticket(services, oidc, properties));
        properties.ExpiresUtc.ShouldEqual(hours is { } value ? _clock.GetUtcNow().AddHours(value) : null);
        properties.AllowRefresh.ShouldEqual(allowRefresh);
        properties.IssuedUtc.ShouldEqual(hours is null ? null : _clock.GetUtcNow());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task should_leave_the_primary_session_policy_untouched_for_links(bool oidc)
    {
        await using var services = Services("02:00:00", false, true);
        var properties = new AuthenticationProperties();
        properties.Items[LinkMiddleware.LinkModePropertyKey] = "true";
        var context = Ticket(services, oidc, properties);
        await Receive(context);
        context.Result.Handled.ShouldBeTrue();
        properties.ExpiresUtc.ShouldBeNull();
        properties.AllowRefresh.ShouldBeNull();
    }

    [Fact]
    public async Task should_not_apply_a_lifetime_when_canonical_identity_fails()
    {
        await using var services = Services("02:00:00", false);
        services.GetRequiredService<IOptionsMonitor<C.Authentication>>().CurrentValue.OidcProviders[0].CanonicalIdentity = new C.CanonicalIdentity
        {
            ProviderKey = "workforce",
            SubjectClaimType = "missing-subject"
        };
        var properties = new AuthenticationProperties();
        var context = Ticket(services, true, properties);
        await Receive(context);
        context.Result.Failure.ShouldNotBeNull();
        properties.ExpiresUtc.ShouldBeNull();
        properties.AllowRefresh.ShouldBeNull();
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task should_keep_the_cookie_session_scoped_and_its_security_attributes(bool oidc)
    {
        await using var services = Services("02:00:00", false);
        var properties = new AuthenticationProperties();
        var context = Ticket(services, oidc, properties);
        context.HttpContext.Request.Scheme = "https";
        await Receive(context);
        await context.HttpContext.SignInAsync("Cookies", context.Principal!, properties);
        var header = context.Response.Headers.SetCookie.Single(value => value!.StartsWith(C.Session.DefaultCookieName + "=", StringComparison.Ordinal))!;
        header.ShouldContain("secure");
        header.ShouldContain("httponly");
        header.ShouldContain("samesite=lax");
        header.Contains("expires=", StringComparison.OrdinalIgnoreCase).ShouldBeFalse();
        header.Contains("max-age=", StringComparison.OrdinalIgnoreCase).ShouldBeFalse();
        properties.IsPersistent.ShouldBeFalse();
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [InlineData(true, true)]
    [InlineData(false, true)]
    public async Task should_renew_only_when_permitted_using_the_provider_span(bool sliding, bool removed)
    {
        await using var services = Services("02:00:00", sliding, true);
        var options = services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get("Cookies");
        options.TimeProvider = _clock;
        var properties = new AuthenticationProperties();
        var context = Ticket(services, true, properties);
        await Receive(context);
        await context.HttpContext.SignInAsync("Cookies", context.Principal!, properties);
        var original = context.Response.Headers.SetCookie.Single(value => value!.StartsWith(options.Cookie.Name + "=", StringComparison.Ordinal))!;
        var cookie = original.Split(';')[0].Split('=', 2)[1];
        if (removed) services.GetRequiredService<IOptionsMonitor<C.Authentication>>().CurrentValue.OidcProviders.Clear();
        _clock.Advance(TimeSpan.FromMinutes(61));
        await using var scope = services.CreateAsyncScope();
        var request = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        request.Request.Headers.Cookie = $"{options.Cookie.Name}={cookie}";
        var handler = new for_SessionLifetimePolicy.given.a_cookie_handler(
            services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>(),
            services.GetRequiredService<ILoggerFactory>());
        await handler.InitializeAsync(new AuthenticationScheme("Cookies", null, typeof(CookieAuthenticationHandler)), request);
        (await handler.AuthenticateAsync()).Succeeded.ShouldBeTrue();
        await handler.Complete();
        var renewed = request.Response.Headers.SetCookie.FirstOrDefault(value => value!.StartsWith(options.Cookie.Name + "=", StringComparison.Ordinal));
        if (!sliding)
        {
            renewed.ShouldBeNull();
            return;
        }
        var ticket = options.TicketDataFormat.Unprotect(renewed!.Split(';')[0].Split('=', 2)[1])!;
        ticket.Properties.IssuedUtc.ShouldEqual(_clock.GetUtcNow());
        (ticket.Properties.ExpiresUtc - ticket.Properties.IssuedUtc).ShouldEqual(TimeSpan.FromHours(2));
    }

    [Fact]
    public void should_register_validation_for_bound_root_options()
    {
        using var services = Services("13:00:00", null);
        var exception = Catch.Exception(() => _ = services.GetRequiredService<IOptionsMonitor<C.AuthProxy>>().CurrentValue);
        exception.ShouldBeOfExactType<OptionsValidationException>();
    }
}
