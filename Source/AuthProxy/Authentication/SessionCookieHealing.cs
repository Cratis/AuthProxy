// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Net.Http.Headers;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Deletes the stale host-only copies of the session cookie that a move to a shared domain or to another cookie
/// name leaves behind in a browser.
/// </summary>
/// <remarks>
/// A browser that signed in before <see cref="C.Session.CookieDomain"/> was configured holds a host-only session
/// cookie, and after the move it also holds the domain cookie, with the same name and path. Only one of them is
/// read, and the chunks of the two can be mixed, which surfaces as a session that fails to decrypt. Host-only and
/// domain cookies are separate entries in the browser, so a deletion issued <em>without</em> a <c language="text">Domain</c>
/// attribute removes only the stale copy and never the shared one.
/// <para>
/// A rename has the same problem in a milder form: the old default-named cookie, and its chunks, would keep
/// inflating every request header. Only host-only copies are ever deleted. A domain cookie that bears the old
/// name may belong to another AuthProxy under the same parent domain and is left alone.
/// </para>
/// <para>
/// When the request is for the cookie domain itself, the browser may not tell a host-only cookie from the domain
/// cookie, so nothing is deleted there. Everything here is a no-op when neither a domain nor a name is configured.
/// </para>
/// </remarks>
public static class SessionCookieHealing
{
    /// <summary>
    /// Gets whether the configuration can leave stale host-only copies behind, and therefore needs the cleanup.
    /// </summary>
    /// <param name="session">The session configuration.</param>
    /// <returns><see langword="true"/> when a domain is set or the cookie is not named the default; otherwise <see langword="false"/>.</returns>
    public static bool IsRequired(C.Session session) =>
        SessionCookie.DomainOf(session) is not null
        || !string.Equals(SessionCookie.NameOf(session), C.Session.DefaultCookieName, StringComparison.Ordinal);

    /// <summary>
    /// Deletes the host-only copies of the session cookie, and of the default-named one after a rename, together
    /// with their chunks. Called when a session is established and when it is terminated.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> whose response the delete cookies are written to.</param>
    /// <param name="session">The session configuration.</param>
    public static void DeleteHostOnlyCopies(HttpContext context, C.Session session)
    {
        if (!IsRequired(session) || !CanDeleteHostOnly(context, session))
        {
            return;
        }

        var name = SessionCookie.NameOf(session);
        if (SessionCookie.DomainOf(session) is not null)
        {
            DeleteHostOnly(context, name);
        }

        if (!string.Equals(name, C.Session.DefaultCookieName, StringComparison.Ordinal))
        {
            DeleteHostOnly(context, C.Session.DefaultCookieName);
        }
    }

    /// <summary>
    /// Deletes the host-only copy of the session cookie when the request carries the cookie more than once, which
    /// is what a browser holding both the old host-only copy and the shared domain cookie sends.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> whose request to inspect and whose response to write to.</param>
    /// <param name="session">The session configuration.</param>
    /// <returns><see langword="true"/> when a duplicate was found and the host-only copy was deleted; otherwise <see langword="false"/>.</returns>
    public static bool DeleteDuplicatedHostOnlyCopy(HttpContext context, C.Session session)
    {
        if (SessionCookie.DomainOf(session) is null || !CanDeleteHostOnly(context, session))
        {
            return false;
        }

        var name = SessionCookie.NameOf(session);
        var duplicated = RequestCookieNames(context)
            .Where(_ => BelongsTo(name, _))
            .GroupBy(_ => _, StringComparer.Ordinal)
            .Any(_ => _.Count() > 1);

        if (!duplicated)
        {
            return false;
        }

        DeleteHostOnly(context, name);
        return true;
    }

    /// <summary>
    /// Gets whether the request carries the session cookie, or one of its chunks.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> whose request to inspect.</param>
    /// <param name="session">The session configuration.</param>
    /// <returns><see langword="true"/> when the cookie is present; otherwise <see langword="false"/>.</returns>
    public static bool IsPresent(HttpContext context, C.Session session)
    {
        var name = SessionCookie.NameOf(session);
        return RequestCookieNames(context).Any(_ => BelongsTo(name, _));
    }

    static bool CanDeleteHostOnly(HttpContext context, C.Session session)
    {
        var domain = SessionCookie.DomainOf(session)?.TrimStart('.');
        return domain is null
            || !string.Equals(context.Request.Host.Host, domain, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Appends an expiry for the host-only copy of a cookie, and of each chunk the request carries.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> whose response the expiry is written to.</param>
    /// <param name="name">The cookie name.</param>
    /// <remarks>
    /// The header is appended directly rather than through <c language="text">Response.Cookies.Delete</c>. That method also drops
    /// every <c language="text">Set-Cookie</c> this response already carries for the same name and path, and the shared cookie
    /// being written or deleted by the cookie scheme is exactly such a header: a host-only deletion issued through it
    /// would silently remove the very cookie it is meant to leave alone.
    /// </remarks>
    static void DeleteHostOnly(HttpContext context, string name)
    {
        foreach (var target in RequestCookieNames(context).Where(_ => IsChunkOf(name, _)).Prepend(name).Distinct(StringComparer.Ordinal))
        {
            var expiry = new SetCookieHeaderValue(target, string.Empty)
            {
                Expires = DateTimeOffset.UnixEpoch,
                Path = "/",
                Secure = context.Request.IsHttps
            };

            context.Response.Headers.Append(HeaderNames.SetCookie, expiry.ToString());
        }
    }

    static bool BelongsTo(string name, string candidate) =>
        string.Equals(candidate, name, StringComparison.Ordinal) || IsChunkOf(name, candidate);

    static bool IsChunkOf(string name, string candidate) =>
        candidate.StartsWith(name, StringComparison.Ordinal)
        && candidate.Length > name.Length + 1
        && candidate[name.Length] == 'C'
        && candidate.Skip(name.Length + 1).All(char.IsAsciiDigit);

    /// <summary>
    /// Gets the name of every cookie in the raw Cookie header, repeats included. <c language="text">HttpRequest.Cookies</c>
    /// collapses repeated names, which is precisely what has to be seen here.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> whose request to inspect.</param>
    /// <returns>The cookie names, in the order they were sent.</returns>
    static IEnumerable<string> RequestCookieNames(HttpContext context) =>
        context.Request.Headers.Cookie
            .SelectMany(_ => (_ ?? string.Empty).Split(';'))
            .Select(_ => _.Trim())
            .Where(_ => _.Length > 0)
            .Select(_ => _.Split('=', 2)[0].Trim());
}
