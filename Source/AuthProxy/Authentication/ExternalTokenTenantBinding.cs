// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Cratis.AuthProxy.Tenancy;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>Establishes and reads the general JWT handler's credential tenant.</summary>
static class ExternalTokenTenantBinding
{
    /// <summary>The proxy-owned tenant marker, never trusted from an issuer.</summary>
    internal const string TenantClaimType = "Cratis.AuthProxy.ExternalTokenTenant";

    /// <summary>Replaces inbound markers and establishes the validated token's tenant when required.</summary>
    /// <param name="context">The successful JWT validation context.</param>
    /// <param name="settings">The tenant binding settings.</param>
    internal static void Apply(TokenValidatedContext context, C.ExternalTokenTenantBinding settings)
    {
        if (context.Principal is not { } principal) return;

        RemoveInboundMarkers(principal);

        if (!settings.Require) return;

        // Read the validated token before inbound claim-name mapping, without changing legacy JWT options.
        var claims = context.SecurityToken switch
        {
            JsonWebToken token => token.Claims,
            JwtSecurityToken token => token.Claims,
            _ => principal.Claims,
        };
        if (!TryResolveTenant(claims, settings, out var tenant))
        {
            context.Fail("The external token does not establish a tenant.");
            return;
        }

        principal.AddIdentity(new ClaimsIdentity([new Claim(TenantClaimType, tenant)], JwtBearerDefaults.AuthenticationScheme));
    }

    /// <summary>Resolves exactly one external tenant claim without normalizing its value.</summary>
    /// <param name="claims">The validated token claims.</param>
    /// <param name="settings">The tenant binding settings.</param>
    /// <param name="tenant">The resolved AuthProxy tenant.</param>
    /// <returns>Whether a usable tenant was established.</returns>
    internal static bool TryResolveTenant(IEnumerable<Claim> claims, C.ExternalTokenTenantBinding settings, out string tenant)
    {
        tenant = string.Empty;
        if (!SingleClaimValue.TryGetSingleValue(claims, settings.TenantClaimType, out var external, trim: false)
            || string.IsNullOrWhiteSpace(external))
        {
            return false;
        }

        if (settings.TenantMapping.Count == 0)
        {
            tenant = external;
        }
        else
        {
            // Configuration binding can supply a case-insensitive dictionary. Matching is always ordinal.
            var mapping = settings.TenantMapping.FirstOrDefault(_ => string.Equals(_.Key, external, StringComparison.Ordinal));
            tenant = mapping.Value ?? string.Empty;
        }

        return TenantIdentifier.IsUsable(tenant);
    }

    /// <summary>Reads only the proxy-owned marker on a JWT Bearer identity.</summary>
    /// <param name="principal">The authenticated principal.</param>
    /// <returns>The credential tenant, or null when unbound.</returns>
    internal static string? BoundTenant(ClaimsPrincipal principal)
    {
        var claims = principal.Identities
            .Where(_ => _.IsAuthenticated && _.AuthenticationType == JwtBearerDefaults.AuthenticationScheme)
            .SelectMany(_ => _.Claims);
        return SingleClaimValue.TryGetSingleValue(claims, TenantClaimType, out var tenant, trim: false)
            && TenantIdentifier.IsUsable(tenant) ? tenant : null;
    }

    static void RemoveInboundMarkers(ClaimsPrincipal principal)
    {
        // Only this handler can establish the marker, never an issuer-supplied claim.
        foreach (var identity in principal.Identities)
        {
            foreach (var claim in identity.Claims.Where(_ => _.Type == TenantClaimType).ToArray())
            {
                identity.RemoveClaim(claim);
            }
        }
    }
}
