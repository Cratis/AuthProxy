// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// Always resolves to the tenant ID specified in the <c>tenantId</c> option.
/// Used for single-tenant deployments.
/// </summary>
/// <param name="config">The options monitor providing the current auth proxy configuration.</param>
public class SpecifiedSourceIdentifierStrategy(IOptionsMonitor<C.AuthProxy> config) : ISourceIdentifierStrategyTyped<SpecifiedOptions>
{
    /// <inheritdoc/>
    public C.TenantSourceIdentifierResolverType Type => C.TenantSourceIdentifierResolverType.Specified;

    /// <inheritdoc/>
    public bool TryResolveSourceIdentifier(HttpContext context, SpecifiedOptions typedOptions, out string sourceIdentifier)
    {
        sourceIdentifier = typedOptions.TenantId
             ?? ResolveTenantIdFromOptions()
             ?? string.Empty;

        return !string.IsNullOrEmpty(sourceIdentifier);
    }

    string? ResolveTenantIdFromOptions()
    {
        foreach (var resolution in config.CurrentValue.TenantResolutions)
        {
            if (resolution.Strategy != C.TenantSourceIdentifierResolverType.Specified)
            {
                continue;
            }

            var tenantId = resolution.Options["tenantId"]?.ToString()
                ?? resolution.Options["TenantId"]?.ToString();

            if (!string.IsNullOrWhiteSpace(tenantId))
            {
                return tenantId;
            }
        }

        return null;
    }
}
