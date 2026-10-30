// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links;
using Microsoft.AspNetCore.Authentication;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Decides how a freshly received provider ticket is routed.
/// </summary>
/// <remarks>
/// The policy only decides. Cookie cleanup, principal replacement, linking, session stamping and notification stay
/// with the authentication pipeline, in their original order.
/// </remarks>
static class TicketReceivedPolicy
{
    /// <summary>
    /// Routes a ticket. An unresolved canonical identity fails before an exact link marker, which is checked
    /// before a normal sign-in.
    /// </summary>
    /// <param name="resolution">The fresh canonical identity resolution.</param>
    /// <param name="properties">The ticket authentication properties.</param>
    /// <returns>The <see cref="TicketReceivedRoute"/> for the ticket.</returns>
    internal static TicketReceivedRoute Route(CanonicalIdentityResolution resolution, AuthenticationProperties? properties)
    {
        if (IsUnresolvedCanonicalIdentity(resolution))
        {
            return TicketReceivedRoute.Fail;
        }

        return IsLinkMode(properties) ? TicketReceivedRoute.CompleteLink : TicketReceivedRoute.CompleteSignIn;
    }

    /// <summary>
    /// Gets a value indicating whether the protocol assurance claim is recorded on the principal.
    /// </summary>
    /// <param name="resolution">The fresh canonical identity resolution.</param>
    /// <param name="canonicalIdentity">The canonical identity contract configured for the provider, when present.</param>
    /// <returns><see langword="true"/> when assurance is recorded; otherwise <see langword="false"/>.</returns>
    internal static bool RecordsProtocolAssurance(CanonicalIdentityResolution resolution, C.CanonicalIdentity? canonicalIdentity) =>
        resolution.IsConfigured && canonicalIdentity is not null;

    /// <summary>
    /// Gets a value indicating whether the registration fingerprint is stamped on a normal sign-in.
    /// </summary>
    /// <param name="resolution">The fresh canonical identity resolution.</param>
    /// <returns><see langword="true"/> when the fingerprint is stamped; otherwise <see langword="false"/>.</returns>
    internal static bool RecordsRegistrationFingerprint(CanonicalIdentityResolution resolution) =>
        resolution.IsConfigured;

    static bool IsUnresolvedCanonicalIdentity(CanonicalIdentityResolution resolution) =>
        resolution.IsConfigured && (!resolution.Succeeded || resolution.Principal is null);

    static bool IsLinkMode(AuthenticationProperties? properties) =>
        properties is not null
        && properties.Items.TryGetValue(LinkMiddleware.LinkModePropertyKey, out var linkMode)
        && linkMode == "true";
}
