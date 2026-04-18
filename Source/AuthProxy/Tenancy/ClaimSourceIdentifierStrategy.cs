// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// Resolves the tenant source identifier from a claim in the <c>x-ms-client-principal</c>
/// that is already present on the request (set by a prior authentication step).
/// Uses the Microsoft standard tenant claim
/// <c>http://schemas.microsoft.com/identity/claims/tenantid</c> by default,
/// but the claim type can be overridden via the <c>claimType</c> option.
/// </summary>
public class ClaimSourceIdentifierStrategy : ISourceIdentifierStrategyTyped<ClaimOptions>
{
    const string DefaultClaimType = "http://schemas.microsoft.com/identity/claims/tenantid";

    /// <inheritdoc/>
    public C.TenantSourceIdentifierResolverType Type => C.TenantSourceIdentifierResolverType.Claim;

    /// <inheritdoc/>
    public bool TryResolveSourceIdentifier(HttpContext context, ClaimOptions typedOptions, out string sourceIdentifier)
    {
        sourceIdentifier = string.Empty;

        var claimType = typedOptions.ClaimType ?? DefaultClaimType;

        // Try from the authenticated ClaimsPrincipal first (richest source).
        var claimValue = context.User.FindFirst(claimType)?.Value;
        if (!string.IsNullOrEmpty(claimValue))
        {
            sourceIdentifier = claimValue;
            return true;
        }

        // Fall back to the x-ms-client-principal header if present.
        var base64Header = context.Request.Headers[Headers.Principal].FirstOrDefault();
        if (ClientPrincipal.TryFromBase64(base64Header, out var principal))
        {
            var match = principal?.Claims.FirstOrDefault(c =>
                 string.Equals(c.Type, claimType, StringComparison.OrdinalIgnoreCase));

            if (match is not null)
            {
                sourceIdentifier = match.Value;
                return true;
            }
        }

        return false;
    }
}
