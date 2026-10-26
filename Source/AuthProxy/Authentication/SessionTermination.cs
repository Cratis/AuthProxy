// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Ends the local session completely: signs the caller out of the cookie authentication scheme and deletes
/// every cookie AuthProxy issues, so nothing of the session survives to confuse the next sign-in.
/// </summary>
/// <remarks>
/// This is the single definition of "logged out locally". The logout endpoint uses it on both legs of an
/// RP-initiated logout, and the identity forwarding guard uses it to terminate a session that can no longer
/// be turned into a forwardable identity. A partial clear is precisely the production failure this exists
/// to prevent: a surviving cookie makes the next visit half-signed-in, which surfaces as anything from a
/// silent re-authentication to a failed provider handshake.
/// </remarks>
public static class SessionTermination
{
    /// <summary>
    /// Signs the current caller out of the cookie scheme and deletes every AuthProxy-issued cookie, plus
    /// any additional cookies the deployment configured (<see cref="C.Logout.AdditionalCookies"/>).
    /// </summary>
    /// <remarks>
    /// The session cookie itself is deleted by the cookie scheme, with the configured domain, so a shared cookie is
    /// removed for every host under it. The stale host-only copies a move to a shared domain or a new cookie name
    /// leaves behind are deleted here too — see <see cref="SessionCookieHealing"/>.
    /// </remarks>
    /// <param name="context">The <see cref="HttpContext"/> whose session to terminate.</param>
    /// <param name="session">The session configuration naming the session cookie.</param>
    /// <param name="logout">The logout configuration naming the additional cookies to delete.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    public static async Task SignOutAndClearCookies(HttpContext context, C.Session session, C.Logout logout)
    {
        // An on-behalf session only ever extends the actor's own, so it ends with it — and the application is told.
        await OnBehalfSessionTermination.End(context, OnBehalfSessionEndReason.ActorSessionEnded);
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        SessionCookieHealing.DeleteHostOnlyCopies(context, session);
        context.Response.Cookies.Delete(Cookies.Identity);
        context.Response.Cookies.Delete(Cookies.IdentityAuthorization);
        context.Response.Cookies.Delete(Cookies.Tenant);
        context.Response.Cookies.Delete(Cookies.Tenants);
        context.Response.Cookies.Delete(Cookies.InviteToken);
        context.Response.Cookies.Delete(Cookies.InvitationEntryState);
        context.Response.Cookies.Delete(Cookies.InviteToken, new CookieOptions { Path = "/" });
        context.Response.Cookies.Delete(Cookies.InvitationEntryState, new CookieOptions { Path = "/" });
        context.Response.Cookies.Delete(Cookies.Registration);
        context.Response.Cookies.Delete(Cookies.Providers);
        TransientAuthenticationCookies.Clear(context);
        AdditionalLogoutCookies.Clear(context, logout.AdditionalCookies);
    }
}
