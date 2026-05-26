// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// Resolves the tenant directly from the selected-tenant cookie.
/// </summary>
public class SelectionSourceIdentifierStrategy : ISourceIdentifierStrategyTyped<SelectionOptions>
{
    /// <inheritdoc/>
    public C.TenantSourceIdentifierResolverType Type => C.TenantSourceIdentifierResolverType.Selection;

    /// <inheritdoc/>
    public bool TryResolveSourceIdentifier(HttpContext context, SelectionOptions typedOptions, out string sourceIdentifier)
    {
        sourceIdentifier = string.Empty;

        if (!context.Request.Cookies.TryGetValue(Cookies.Tenant, out var tenantId)
            || string.IsNullOrWhiteSpace(tenantId))
        {
            return false;
        }

        sourceIdentifier = tenantId;
        return true;
    }
}
