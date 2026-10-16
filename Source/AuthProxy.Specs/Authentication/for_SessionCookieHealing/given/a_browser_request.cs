// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionCookieHealing.given;

public class a_browser_request : Specification
{
    protected const string Cookie = C.Session.DefaultCookieName;
    protected DefaultHttpContext _context;
    protected C.Session _session;

    void Establish()
    {
        _session = new();
        _context = new DefaultHttpContext();
        _context.Request.Scheme = "https";
        _context.Request.Host = new HostString("operations.example.test");
    }

    protected IReadOnlyList<string> SetCookies => [.. _context.Response.Headers.SetCookie.Select(_ => _ ?? string.Empty)];

    protected void SendCookies(params string[] cookies) => _context.Request.Headers.Cookie = string.Join("; ", cookies);

    protected bool Deleted(string name) => SetCookies.Any(_ => _.StartsWith($"{name}=;", StringComparison.Ordinal) && _.Contains("expires=", StringComparison.OrdinalIgnoreCase));

    protected bool DeletedWithDomain(string name) => SetCookies.Any(_ => _.StartsWith($"{name}=;", StringComparison.Ordinal) && _.Contains("domain=", StringComparison.OrdinalIgnoreCase));
}
