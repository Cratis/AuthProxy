// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_SessionCookieHealingMiddleware.given;

public class a_healing_middleware : Specification
{
    protected const string Cookie = C.Session.DefaultCookieName;
    protected C.Session _session;
    protected DefaultHttpContext _context;
    protected bool _nextWasCalled;
    ServiceProvider _services;
    SessionCookieHealingMiddleware _middleware;

    void Establish()
    {
        _session = new() { CookieDomain = ".example.test" };

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
    }

    protected IReadOnlyList<string> SetCookies => [.. _context.Response.Headers.SetCookie.Select(_ => _ ?? string.Empty)];

    protected void SendCookies(params string[] cookies) => _context.Request.Headers.Cookie = string.Join("; ", cookies);

    protected Task Invoke()
    {
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(new C.AuthProxy { Session = _session });
        _middleware = new SessionCookieHealingMiddleware(
            _ =>
            {
                _nextWasCalled = true;
                return Task.CompletedTask;
            },
            config);

        return _middleware.InvokeAsync(_context);
    }

    protected bool Deleted(string name) => SetCookies.Any(_ => _.StartsWith($"{name}=;", StringComparison.Ordinal) && _.Contains("expires=", StringComparison.OrdinalIgnoreCase));

    void Destroy() => _services.Dispose();
}
