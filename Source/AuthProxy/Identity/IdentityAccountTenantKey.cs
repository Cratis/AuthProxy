// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Combines a validated account binding and tenant into a collision-safe in-memory cache key.
/// </summary>
/// <param name="Purpose">The cache surface using the key.</param>
/// <param name="Account">The validated account binding.</param>
/// <param name="TenantId">The tenant identifier.</param>
internal sealed record IdentityAccountTenantKey(string Purpose, IdentityAccountBinding Account, string TenantId)
{
    /// <summary>
    /// Creates a cache key while preserving the released case-insensitive tenant comparison.
    /// </summary>
    /// <param name="purpose">The cache surface using the key.</param>
    /// <param name="account">The validated account binding.</param>
    /// <param name="tenantId">The tenant identifier.</param>
    /// <returns>A structured account and tenant cache key.</returns>
    public static IdentityAccountTenantKey Create(string purpose, IdentityAccountBinding account, string tenantId) =>
        new(purpose, account, tenantId.ToUpperInvariant());
}
