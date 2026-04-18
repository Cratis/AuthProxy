// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Adds configured invite-token claim mappings to the outbound principal
/// sent to the identity details provider.
/// </summary>
/// <param name="inviteTokenValidator">The invite token validator used to read claims from the invite token.</param>
/// <param name="config">The auth proxy configuration monitor.</param>
public class InviteTokenClaimsPrincipalEnricher(
    IInviteTokenValidator inviteTokenValidator,
    IOptionsMonitor<C.AuthProxy> config) : IIdentityDetailsPrincipalEnricher
{
    /// <inheritdoc/>
    public ClientPrincipal Enrich(HttpContext context, ClientPrincipal principal)
    {
        if (!context.Request.Cookies.TryGetValue(Cookies.InviteToken, out var inviteToken)
            || string.IsNullOrWhiteSpace(inviteToken))
        {
            return principal;
        }

        var mappings = config.CurrentValue.Invite?.ClaimsToForward ?? [];
        if (mappings.Count == 0)
        {
            return principal;
        }

        var claims = principal.Claims.ToList();
        var changed = false;

        foreach (var mapping in mappings)
        {
            if (string.IsNullOrWhiteSpace(mapping.FromClaimType))
            {
                continue;
            }

            if (!inviteTokenValidator.TryGetClaim(inviteToken, mapping.FromClaimType, out var value)
                || string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            var targetClaimType = string.IsNullOrWhiteSpace(mapping.ToClaimType)
                ? mapping.FromClaimType
                : mapping.ToClaimType;

            if (claims.Exists(_ => _.Type == targetClaimType && _.Value == value))
            {
                continue;
            }

            claims.Add(new ClientPrincipalClaim
            {
                Type = targetClaimType,
                Value = value,
            });
            changed = true;
        }

        if (!changed)
        {
            return principal;
        }

        return new ClientPrincipal
        {
            IdentityProvider = principal.IdentityProvider,
            UserId = principal.UserId,
            UserDetails = principal.UserDetails,
            UserRoles = principal.UserRoles,
            Claims = claims,
        };
    }
}
