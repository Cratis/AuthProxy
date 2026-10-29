// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// Resolves the tenant the signed-in user selected, once it has been confirmed for that user. The selected-tenant
/// cookie itself is never read here: the tenant selection step confirms it and records the outcome on the request.
/// </summary>
public class SelectionSourceIdentifierStrategy : ISourceIdentifierStrategyTyped<SelectionOptions>
{
    /// <summary>
    /// The <see cref="HttpContext.Items"/> key holding the tenant that was confirmed for the signed-in user.
    /// </summary>
    public const string ConfirmedTenantItemKey = "Cratis.AuthProxy.ConfirmedSelectedTenant";

    /// <inheritdoc/>
    public C.TenantSourceIdentifierResolverType Type => C.TenantSourceIdentifierResolverType.Selection;

    /// <inheritdoc/>
    public bool TryResolveSourceIdentifier(HttpContext context, SelectionOptions typedOptions, out string sourceIdentifier)
    {
        sourceIdentifier = string.Empty;

        if (context.Items.TryGetValue(ConfirmedTenantItemKey, out var confirmed)
            && confirmed is string tenantId
            && !string.IsNullOrWhiteSpace(tenantId))
        {
            sourceIdentifier = tenantId;
            return true;
        }

        return false;
    }
}
