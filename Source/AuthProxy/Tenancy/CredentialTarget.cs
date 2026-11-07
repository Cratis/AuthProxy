// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Tenancy;

/// <summary>Compares credential constraints with the target without normalizing either value.</summary>
public static class CredentialTarget
{
    /// <summary>Compares a credential constraint exactly with its target.</summary>
    /// <param name="credential">The verified credential constraint.</param>
    /// <param name="target">The requested target.</param>
    /// <returns>Whether the two values are identical.</returns>
    public static bool Matches(string? credential, string? target) => string.Equals(credential, target, StringComparison.Ordinal);

    /// <summary>
    /// Compares tenant identifiers consistently with tenancy resolution.
    /// </summary>
    /// <param name="credential">The verified credential tenant.</param>
    /// <param name="target">The requested tenant.</param>
    /// <returns>Whether the tenant identifiers match, ignoring case.</returns>
    public static bool MatchesTenant(string? credential, string? target) => string.Equals(credential, target, StringComparison.OrdinalIgnoreCase);

    /// <summary>Determines whether a resolution strategy addresses a tenant rather than supplies a fallback or credential.</summary>
    /// <param name="strategy">The resolution strategy.</param>
    /// <param name="bearerRoute">Whether the request uses a bearer route, which ignores Specified deployment tenants.</param>
    /// <returns>Whether the strategy addresses a target tenant.</returns>
    public static bool IsAddressedByRequest(TenantSourceIdentifierResolverType strategy, bool bearerRoute) =>
        strategy is TenantSourceIdentifierResolverType.Host or TenantSourceIdentifierResolverType.SubHost or TenantSourceIdentifierResolverType.Route
        || (!bearerRoute && strategy == TenantSourceIdentifierResolverType.Specified);
}
