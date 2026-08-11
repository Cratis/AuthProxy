// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Removes the cookies that carry a pending invitation across the provider round-trip.
/// </summary>
/// <remarks>
/// Shared between <see cref="InviteMiddleware"/> and <see cref="InviteCallbackCompletion"/> so the pending
/// state is cleared identically wherever an invitation reaches its terminal answer.
/// </remarks>
public static class PendingInvitationCookies
{
    /// <summary>
    /// Removes every cookie belonging to a pending invitation, at both the default and the root path.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    public static void Delete(HttpContext context)
    {
        context.Response.Cookies.Delete(Cookies.InviteToken);
        context.Response.Cookies.Delete(Cookies.InvitationEntryState);
        context.Response.Cookies.Delete(Cookies.InviteToken, new CookieOptions { Path = "/" });
        context.Response.Cookies.Delete(Cookies.InvitationEntryState, new CookieOptions { Path = "/" });
    }
}
