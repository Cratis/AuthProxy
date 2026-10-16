// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_SessionTermination;

public class when_terminating_a_session_without_a_cookie_domain : Specification
{
    const string Cookie = C.Session.DefaultCookieName;

    DefaultHttpContext _context;
    ServiceProvider _services;
    C.Session _session;

    void Establish()
    {
        _session = new C.Session();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDataProtection();
        services
            .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(options => SessionCookie.Apply(options.Cookie, _session));

        _services = services.BuildServiceProvider();
        _context = new DefaultHttpContext { RequestServices = _services };
        _context.Request.Scheme = "https";
        _context.Request.Host = new HostString("operations.example.test");
        _context.Request.Headers.Cookie = $"{Cookie}=session";
    }

    async Task Because() => await SessionTermination.SignOutAndClearCookies(_context, _session, new C.Logout());

    void Destroy() => _services.Dispose();

    [Fact] void should_expire_the_host_only_cookie() => SetCookies.Any(_ => _.StartsWith($"{Cookie}=;", StringComparison.Ordinal)).ShouldBeTrue();
    [Fact] void should_not_name_any_domain() => SetCookies.Any(_ => _.Contains("domain=", StringComparison.OrdinalIgnoreCase)).ShouldBeFalse();
    [Fact] void should_expire_the_cookie_exactly_once() => SetCookies.Count(_ => _.StartsWith($"{Cookie}=;", StringComparison.Ordinal)).ShouldEqual(1);

    string[] SetCookies => [.. _context.Response.Headers.SetCookie.Select(_ => _ ?? string.Empty)];
}
