// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_SessionTermination;

public class when_terminating_a_session_under_a_cookie_domain : Specification
{
    const string Domain = ".example.test";
    const string Cookie = C.Session.DefaultCookieName;

    DefaultHttpContext _context;
    ServiceProvider _services;

    void Establish()
    {
        var session = new C.Session { CookieDomain = Domain };
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDataProtection();
        services
            .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(options => SessionCookie.Apply(options.Cookie, session));

        _services = services.BuildServiceProvider();
        _context = new DefaultHttpContext { RequestServices = _services };
        _context.Request.Scheme = "https";
        _context.Request.Host = new HostString("operations.example.test");
        _context.Request.Path = "/.cratis/logout";
        _context.Request.Headers.Cookie = $"{Cookie}=chunks-1; {Cookie}C1=first";
        _sessionUnderTest = session;
    }

    C.Session _sessionUnderTest;

    async Task Because() => await SessionTermination.SignOutAndClearCookies(_context, _sessionUnderTest, new C.Logout());

    void Destroy() => _services.Dispose();

    [Fact] void should_expire_the_shared_cookie_for_the_domain() => SetCookies.Any(_ => IsDeletionOf(_, Cookie) && _.Contains($"domain={Domain}", StringComparison.OrdinalIgnoreCase)).ShouldBeTrue();
    [Fact] void should_expire_the_shared_chunk_for_the_domain() => SetCookies.Any(_ => IsDeletionOf(_, $"{Cookie}C1") && _.Contains($"domain={Domain}", StringComparison.OrdinalIgnoreCase)).ShouldBeTrue();
    [Fact] void should_also_expire_the_host_only_copy() => SetCookies.Any(_ => IsDeletionOf(_, Cookie) && !_.Contains("domain=", StringComparison.OrdinalIgnoreCase)).ShouldBeTrue();
    [Fact] void should_also_expire_the_host_only_chunk() => SetCookies.Any(_ => IsDeletionOf(_, $"{Cookie}C1") && !_.Contains("domain=", StringComparison.OrdinalIgnoreCase)).ShouldBeTrue();

    string[] SetCookies => [.. _context.Response.Headers.SetCookie.Select(_ => _ ?? string.Empty)];

    static bool IsDeletionOf(string setCookie, string name) => setCookie.StartsWith($"{name}=;", StringComparison.Ordinal);
}
