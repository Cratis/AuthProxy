// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Middleware that removes the stale host-only copy of the session cookie a browser keeps after the session
/// moved to a shared <see cref="C.Session.CookieDomain"/>.
/// </summary>
/// <remarks>
/// It runs right after authentication so it can also tell a session cookie that could not be turned into a
/// ticket — one that failed to decrypt or expired — from one that is simply absent. It never changes the request
/// itself and does nothing at all when the deployment configures neither a cookie domain nor a cookie name. See
/// <see cref="SessionCookieHealing"/> for what is deleted and what is deliberately left alone.
/// </remarks>
/// <param name="next">The next middleware in the pipeline.</param>
/// <param name="config">The auth proxy configuration monitor.</param>
public class SessionCookieHealingMiddleware(RequestDelegate next, IOptionsMonitor<C.AuthProxy> config)
{
    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public async Task InvokeAsync(HttpContext context)
    {
        var session = config.CurrentValue.Session;
        if (SessionCookie.DomainOf(session) is not null)
        {
            await Heal(context, session);
        }

        await next(context);
    }

    static async Task Heal(HttpContext context, C.Session session)
    {
        if (SessionCookieHealing.DeleteDuplicatedHostOnlyCopy(context, session))
        {
            return;
        }

        if (context.User.Identity?.IsAuthenticated != true
            && SessionCookieHealing.IsPresent(context, session))
        {
            var result = await context.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (!result.Succeeded)
            {
                SessionCookieHealing.DeleteHostOnlyCopies(context, session);
            }
        }
    }
}
