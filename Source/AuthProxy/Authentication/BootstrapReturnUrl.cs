// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Preserves pending bootstrap sign-ins for their destination and clears abandoned flow state.
/// </summary>
internal static class BootstrapReturnUrl
{
    /// <summary>
    /// Validates a pending flow's local destination, clearing the flow when ordinary sign-in resumes.
    /// </summary>
    /// <param name="context">The current request.</param>
    /// <param name="returnUrl">The requested destination after sign-in.</param>
    /// <returns>Whether sign-in may continue without an unsafe external destination.</returns>
    internal static bool PrepareLogin(HttpContext context, string? returnUrl)
    {
        if (!context.HasPendingRegistration() && !context.HasPendingInvitation()) return true;
        returnUrl = string.IsNullOrEmpty(returnUrl) ? RelativeRedirect.ApplicationRoot : returnUrl;
        if (!RelativeRedirect.IsSameSiteRelative(returnUrl)) return false;
        if (BelongsToPendingFlow(context, returnUrl)) return true;

        context.Response.Cookies.Delete(Cookies.Registration);
        PendingInvitationCookies.Delete(context);
        var remaining = context.Request.Cookies.Where(cookie => cookie.Key is not Cookies.Registration and not Cookies.InviteToken and not Cookies.InvitationEntryState);
        context.Request.Headers.Cookie = string.Join("; ", remaining.Select(cookie => $"{cookie.Key}={Uri.EscapeDataString(cookie.Value)}"));
        return true;
    }

    static bool BelongsToPendingFlow(HttpContext context, string returnUrl)
    {
        var path = returnUrl.Split('?', '#')[0];
        if (context.HasPendingRegistration() && string.Equals(path, WellKnownPaths.Registration, StringComparison.OrdinalIgnoreCase)) return true;

        return context.TryGetPendingInvitationToken(out var token)
            && string.Equals(path, $"{WellKnownPaths.InvitePathPrefix}/{token}", StringComparison.Ordinal);
    }
}
