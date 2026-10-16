// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// The one place that knows the name and the domain of the session cookie.
/// </summary>
/// <remarks>
/// The cookie handler, the sign-out and the stale-cookie cleanup all ask here, so they cannot disagree about
/// which cookie the session lives in. With nothing configured the name is <see cref="C.Session.DefaultCookieName"/>
/// and there is no domain, which is a host-only cookie exactly as it always was.
/// </remarks>
public static class SessionCookie
{
    /// <summary>
    /// Gets the name of the session cookie.
    /// </summary>
    /// <param name="session">The session configuration.</param>
    /// <returns>The configured name, or <see cref="C.Session.DefaultCookieName"/> when none is configured.</returns>
    public static string NameOf(C.Session session) =>
        string.IsNullOrWhiteSpace(session.CookieName) ? C.Session.DefaultCookieName : session.CookieName.Trim();

    /// <summary>
    /// Gets the domain the session cookie is scoped to.
    /// </summary>
    /// <param name="session">The session configuration.</param>
    /// <returns>The configured domain, or <see langword="null"/> for a host-only cookie.</returns>
    public static string? DomainOf(C.Session session) =>
        string.IsNullOrWhiteSpace(session.CookieDomain) ? null : session.CookieDomain.Trim();

    /// <summary>
    /// Applies the name and domain of the session cookie to a cookie builder.
    /// </summary>
    /// <param name="cookie">The <see cref="CookieBuilder"/> of the cookie authentication handler.</param>
    /// <param name="session">The session configuration.</param>
    public static void Apply(CookieBuilder cookie, C.Session session)
    {
        cookie.Name = NameOf(session);
        cookie.Domain = DomainOf(session);
    }
}
