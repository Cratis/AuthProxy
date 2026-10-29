// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Ends the on-behalf session a request carries from places that end sessions without owning on-behalf sessions:
/// logout, session termination and identity refusal.
/// </summary>
/// <remarks>
/// Those paths are static or predate on-behalf sessions, so the sessions are resolved from the request's services
/// the same way the authentication events resolve theirs. Where none are registered the cookie is still removed,
/// so no path that ends the actor's session can leave an on-behalf session behind.
/// </remarks>
public static class OnBehalfSessionTermination
{
    /// <summary>
    /// Ends the on-behalf session the request carries, if any.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="reason">Why it ends.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    public static async Task End(HttpContext context, OnBehalfSessionEndReason reason)
    {
        if (!context.Request.Cookies.ContainsKey(Cookies.OnBehalf))
        {
            return;
        }

        if (context.RequestServices?.GetService<IOnBehalfSessions>() is { } sessions)
        {
            await sessions.End(context, reason);
            return;
        }

        OnBehalfSessionCookie.Delete(context);
    }
}
