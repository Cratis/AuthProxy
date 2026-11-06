// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Restricts pending bootstrap sign-ins to the proxy-owned destination that completes their flow.
/// </summary>
internal static class BootstrapReturnUrl
{
    /// <summary>
    /// Determines whether a return URL belongs to the pending registration or invitation.
    /// </summary>
    /// <param name="context">The current request.</param>
    /// <param name="returnUrl">The requested destination after sign-in.</param>
    /// <returns>Whether no bootstrap is pending or the destination is an allowed local path.</returns>
    internal static bool IsAllowed(HttpContext context, string? returnUrl)
    {
        if (!context.HasPendingRegistration() && !context.HasPendingInvitation()) return true;
        if (!RelativeRedirect.IsSameSiteRelative(returnUrl)) return false;

        var path = returnUrl!.Split('?', '#')[0];
        if (context.HasPendingRegistration() && string.Equals(path, WellKnownPaths.Registration, StringComparison.OrdinalIgnoreCase)) return true;

        return context.TryGetPendingInvitationToken(out var token)
            && string.Equals(path, $"{WellKnownPaths.InvitePathPrefix}/{token}", StringComparison.Ordinal);
    }
}
