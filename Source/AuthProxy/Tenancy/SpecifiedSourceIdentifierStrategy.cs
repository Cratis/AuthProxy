// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// Always resolves to the tenant ID specified in the <c>tenantId</c> option.
/// Used for single-tenant deployments.
/// </summary>
public class SpecifiedSourceIdentifierStrategy : ISourceIdentifierStrategyTyped<SpecifiedOptions>
{
    /// <inheritdoc/>
    public C.TenantSourceIdentifierResolverType Type => C.TenantSourceIdentifierResolverType.Specified;

    /// <inheritdoc/>
    public bool TryResolveSourceIdentifier(HttpContext context, SpecifiedOptions typedOptions, out string sourceIdentifier)
    {
        sourceIdentifier = typedOptions.TenantId?.Trim() ?? string.Empty;
        return !string.IsNullOrEmpty(sourceIdentifier);
    }
}
