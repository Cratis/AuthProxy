// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

public class when_configuring_cookie_authentication_with_custom_session_settings : Specification
{
    CookieAuthenticationOptions _options;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.Session.SectionKey}:Lifetime"] = "02:30:00",
            [$"{C.Session.SectionKey}:SlidingExpiration"] = "true"
        });

        builder.AddIngressAuthentication();

        var serviceProvider = builder.Services.BuildServiceProvider();
        var monitor = serviceProvider.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>();
        _options = monitor.Get(CookieAuthenticationDefaults.AuthenticationScheme);
    }

    [Fact] void should_use_the_configured_lifetime() => _options.ExpireTimeSpan.ShouldEqual(TimeSpan.FromHours(2.5));
    [Fact] void should_use_the_configured_sliding_expiration() => _options.SlidingExpiration.ShouldBeTrue();
}
