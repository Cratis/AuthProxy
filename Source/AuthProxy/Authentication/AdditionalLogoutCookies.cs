// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Deletes the deployment-configured additional cookies (<see cref="C.Logout.AdditionalCookies"/>) —
/// cookies AuthProxy does not issue itself but that must not survive a session termination, such as a
/// session cookie another proxy scoped to a parent domain. Matching is by exact name only.
/// </summary>
/// <remarks>
/// Every deletion is issued at the root path with the Secure attribute mirroring the request scheme, so it
/// matches how such cookies are typically written and is not discarded by the browser. A cookie scoped to
/// a parent domain (e.g. <c>.cratis.studio</c>) is invisible to a host-scoped deletion, so when an entry
/// carries a domain the deletion is issued for that domain as well — deleting for a parent domain of the
/// current host is legal, which is exactly what makes it possible to kill such a straggler from here.
/// </remarks>
public static class AdditionalLogoutCookies
{
    /// <summary>
    /// Deletes every configured additional cookie, for the request host and, when configured, its domain.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> whose response the delete cookies are written to.</param>
    /// <param name="cookies">The configured cookies to delete.</param>
    public static void Clear(HttpContext context, IEnumerable<C.LogoutCookie> cookies)
    {
        foreach (var cookie in cookies.Where(_ => !string.IsNullOrWhiteSpace(_.Name)))
        {
            context.Response.Cookies.Delete(cookie.Name, DeletionOptions(context));

            if (!string.IsNullOrWhiteSpace(cookie.Domain))
            {
                var domainScoped = DeletionOptions(context);
                domainScoped.Domain = cookie.Domain;
                context.Response.Cookies.Delete(cookie.Name, domainScoped);
            }
        }
    }

    static CookieOptions DeletionOptions(HttpContext context) => new()
    {
        Path = "/",
        Secure = context.Request.IsHttps
    };
}
