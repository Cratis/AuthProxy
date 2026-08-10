// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Clears the transient correlation and nonce cookies the ASP.NET Core OAuth/OIDC middleware writes for
/// every sign-in handshake. They carry random per-attempt names, so they are matched by their well-known
/// prefixes rather than by an exact name.
/// </summary>
/// <remarks>
/// The provider registrations keep these cookies at the root path so they are sent — and can be cleared —
/// everywhere. Cookies written by earlier AuthProxy versions were scoped to the provider's callback path
/// instead, which makes them invisible to the logout endpoint and immortal from the browser's point of
/// view: they accumulate from abandoned handshakes until the Cookie header itself becomes a liability.
/// The one place they <em>are</em> visible is the callback path itself, so every deletion is issued for
/// both the root path and the current request path — on a provider callback that reaches the legacy
/// path-scoped stragglers too.
/// </remarks>
public static class TransientAuthenticationCookies
{
    /// <summary>
    /// Deletes every transient sign-in handshake cookie the browser sent with the current request.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> whose response the delete cookies are written to.</param>
    public static void Clear(HttpContext context)
    {
        var requestPath = context.Request.Path;
        var alsoClearRequestPathScoped = requestPath.HasValue && requestPath.Value != "/";

        foreach (var cookie in context.Request.Cookies.Keys.Where(IsTransient))
        {
            context.Response.Cookies.Delete(cookie, new CookieOptions { Path = "/" });
            if (alsoClearRequestPathScoped)
            {
                context.Response.Cookies.Delete(cookie, new CookieOptions { Path = requestPath.Value });
            }
        }
    }

    static bool IsTransient(string name) =>
        name.StartsWith(Cookies.CorrelationPrefix, StringComparison.Ordinal)
        || name.StartsWith(Cookies.NoncePrefix, StringComparison.Ordinal);
}
