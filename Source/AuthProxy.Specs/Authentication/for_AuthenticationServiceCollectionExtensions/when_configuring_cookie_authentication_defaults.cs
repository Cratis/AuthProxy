// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

public class when_configuring_cookie_authentication_defaults : Specification
{
    CookieAuthenticationOptions _options;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();

        builder.AddIngressAuthentication();

        var serviceProvider = builder.Services.BuildServiceProvider();
        var monitor = serviceProvider.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>();
        _options = monitor.Get(CookieAuthenticationDefaults.AuthenticationScheme);
    }

    [Fact] void should_make_the_cookie_http_only() => _options.Cookie.HttpOnly.ShouldBeTrue();
    [Fact] void should_use_lax_same_site() => _options.Cookie.SameSite.ShouldEqual(SameSiteMode.Lax);
    [Fact] void should_mark_the_cookie_secure_on_https_requests() => _options.Cookie.SecurePolicy.ShouldEqual(CookieSecurePolicy.SameAsRequest);
    [Fact] void should_keep_the_cookie_session_scoped() => _options.Cookie.Expiration.ShouldBeNull();
    [Fact] void should_bound_the_ticket_lifetime_to_twelve_hours() => _options.ExpireTimeSpan.ShouldEqual(C.Session.DefaultLifetime);
    [Fact] void should_use_an_absolute_lifetime() => _options.SlidingExpiration.ShouldBeFalse();
}
