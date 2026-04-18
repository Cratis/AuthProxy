// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Replaces the outbound principal user ID with the invite token invitation ID (<c>jti</c>)
/// when an invite token cookie is present.
/// </summary>
/// <param name="inviteTokenValidator">The invite token validator used to read the invitation ID claim.</param>
public class InviteTokenInvitationIdPrincipalEnricher(IInviteTokenValidator inviteTokenValidator) : IIdentityDetailsPrincipalEnricher
{
    /// <inheritdoc/>
    public ClientPrincipal Enrich(HttpContext context, ClientPrincipal principal)
    {
        if (!context.Request.Cookies.TryGetValue(Cookies.InviteToken, out var inviteToken)
            || string.IsNullOrWhiteSpace(inviteToken))
        {
            return principal;
        }

        if (!inviteTokenValidator.TryGetClaim(inviteToken, "jti", out var invitationId)
            || string.IsNullOrWhiteSpace(invitationId))
        {
            return principal;
        }

        return new ClientPrincipal
        {
            IdentityProvider = principal.IdentityProvider,
            UserId = invitationId,
            UserDetails = principal.UserDetails,
            UserRoles = principal.UserRoles,
            Claims = principal.Claims,
        };
    }
}
