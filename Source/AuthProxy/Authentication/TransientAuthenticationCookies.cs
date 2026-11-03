// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Clears the transient correlation and nonce cookies the ASP.NET Core OAuth/OIDC middleware writes for
/// every sign-in handshake. They carry random per-attempt names, so they are matched by their well-known
/// prefixes rather than by an exact name.
/// </summary>
/// <remarks>
/// The provider registrations keep these cookies at the root path so they are sent — and can be cleared —
/// everywhere. Cookies written by earlier AuthProxy versions were scoped to the provider's callback path
/// instead; they carried a 15- or 60-minute expiry and none can still exist, so only the root path is cleared.
/// Each deletion is a header of its own (an OIDC nonce deletion is several hundred bytes), and a browser that
/// abandoned several sign-ins holds one pair per attempt. To keep the sign-in callback inside a proxy's
/// response header buffer, the sweep spends at most <see cref="SweepBudget"/> bytes per response: the cookies
/// it does not reach expire on their own within the hour, and the next callback or logout continues the sweep.
/// </remarks>
public static class TransientAuthenticationCookies
{
    /// <summary>
    /// The most response header bytes, measured the way <see cref="SetCookieSizeMiddleware"/> measures them, one sweep may add.
    /// </summary>
    internal const int SweepBudget = 400;

    /// <summary>
    /// Deletes the transient sign-in handshake cookies the browser sent with the current request, within <see cref="SweepBudget"/>.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> whose response the delete cookies are written to.</param>
    public static void Clear(HttpContext context)
    {
        var alreadyDeleted = DeletedNames(context.Response.Headers.SetCookie);
        var spent = 0;

        foreach (var cookie in context.Request.Cookies.Keys.Where(IsTransient))
        {
            if (alreadyDeleted.Contains(cookie))
            {
                continue;
            }

            context.Response.Cookies.Delete(cookie, new CookieOptions { Path = "/" });
            var headers = context.Response.Headers.SetCookie;
            var size = HeaderNames.SetCookie.Length + 2 + headers[^1]!.Length + 2;
            if (spent + size > SweepBudget)
            {
                context.Response.Headers.SetCookie = new StringValues([.. headers.Take(headers.Count - 1)]);
                continue;
            }

            spent += size;
        }
    }

    static HashSet<string> DeletedNames(StringValues setCookies) =>
        [.. setCookies.Where(header => header is not null).Select(header => header![..Math.Max(header.IndexOf('=', StringComparison.Ordinal), 0)])];

    static bool IsTransient(string name) =>
        name.StartsWith(Cookies.CorrelationPrefix, StringComparison.Ordinal)
        || name.StartsWith(Cookies.NoncePrefix, StringComparison.Ordinal);
}
