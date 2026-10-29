// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// Resolves the tenant source identifier from a claim of the signed-in user that AuthProxy authenticated.
/// Uses the Microsoft standard tenant claim
/// <c language="text">http://schemas.microsoft.com/identity/claims/tenantid</c> by default,
/// but the claim type can be overridden via the <c language="text">claimType</c> option.
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

        // Only the principal AuthProxy authenticated is read; a principal header sent by the caller is not.
        var claimValue = context.User.FindFirst(claimType)?.Value;
        if (!string.IsNullOrEmpty(claimValue))
        {
            sourceIdentifier = claimValue;
            return true;
        }

        return false;
    }
}
