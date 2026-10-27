// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics.CodeAnalysis;

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Reads and writes the <see cref="Cookies.OnBehalf"/> cookie.
/// </summary>
/// <param name="protector">The protector the session is sealed with.</param>
/// <remarks>
/// The cookie is host-only, HTTP-only, <c language="text">SameSite=Lax</c> and expires with the session. It is separate from the
/// actor's own session cookie, so ending an on-behalf session never signs the actor out, and signing the actor out
/// always ends the on-behalf session.
/// </remarks>
public sealed class OnBehalfSessionCookie(IOnBehalfSessionProtector protector)
{
    /// <summary>
    /// Removes the session cookie, if the request carries one.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    public static void Delete(HttpContext context)
    {
        if (context.Request.Cookies.ContainsKey(Cookies.OnBehalf))
        {
            context.Response.Cookies.Delete(Cookies.OnBehalf, new CookieOptions { Path = "/" });
        }
    }

    /// <summary>
    /// Reads the session the request carries.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="session">The session.</param>
    /// <returns><see langword="true"/> when the request carries an authentic session cookie; otherwise <see langword="false"/>.</returns>
    public bool TryRead(HttpContext context, [NotNullWhen(true)] out OnBehalfSession? session)
    {
        session = null;
        if (!context.Request.Cookies.TryGetValue(Cookies.OnBehalf, out var value) || string.IsNullOrEmpty(value))
        {
            return false;
        }

        if (!protector.TryUnprotect(value, out var unprotected))
        {
            return false;
        }

        session = unprotected;
        return true;
    }

    /// <summary>
    /// Writes the session cookie to the response.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="session">The session.</param>
    public void Write(HttpContext context, OnBehalfSession session) =>
        context.Response.Cookies.Append(Cookies.OnBehalf, protector.Protect(session), new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Secure = context.Request.IsHttps,
            Path = "/",
            Expires = session.ExpiresAt,
            IsEssential = true,
        });
}
