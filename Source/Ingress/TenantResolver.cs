// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Ingress.Configuration;
using Cratis.Ingress.Tenancy;
using Microsoft.Extensions.Options;

namespace Cratis.Ingress;

/// <summary>
/// Resolves the tenant ID by running the configured resolution strategies in order
/// until one succeeds, then matching the resulting source identifier against the
/// tenant map in <see cref="IngressConfig.Tenants"/>.
/// </summary>
/// <param name="config">The options monitor providing the current ingress configuration.</param>
/// <param name="strategies">The collection of available source identifier resolution strategies.</param>
/// <param name="logger">The logger.</param>
public class TenantResolver(
    IOptionsMonitor<IngressConfig> config,
    IEnumerable<ISourceIdentifierStrategy> strategies,
    ILogger<TenantResolver> logger) : ITenantResolver
{
    /// <inheritdoc/>
    public bool TryResolve(HttpContext context, out Guid tenantId)
    {
        tenantId = Guid.Empty;
        var resolutions = config.CurrentValue.TenantResolutions;

        if (resolutions.Count == 0)
        {
            // No resolution configured – treat as single-tenant with empty tenant ID.
            return true;
        }

        foreach (var resolution in resolutions)
        {
            var strategy = strategies.FirstOrDefault(s => s.Type == resolution.Strategy);
            if (strategy is null)
            {
                continue;
            }

            if (!strategy.TryResolveSourceIdentifier(context, resolution.Options, out var sourceIdentifier))
            {
                continue;
            }

            // Specified strategy returns a fixed Guid directly.
            if (resolution.Strategy == TenantSourceIdentifierResolverType.Specified
                && Guid.TryParse(sourceIdentifier, out var specifiedId))
            {
                tenantId = specifiedId;
                logger.TenantResolvedViaSpecifiedStrategy(tenantId);
                return true;
            }

            // For all other strategies, look up the source identifier in the tenant map.
            foreach (var (id, tenantConfig) in config.CurrentValue.Tenants)
            {
                if (tenantConfig.Domains.Contains(sourceIdentifier, StringComparer.OrdinalIgnoreCase)
                    || tenantConfig.SourceIdentifiers.Contains(sourceIdentifier, StringComparer.OrdinalIgnoreCase))
                {
                    tenantId = id;
                    logger.TenantResolved(resolution.Strategy, sourceIdentifier, tenantId);
                    return true;
                }
            }

            logger.SourceIdentifierMatchedNoTenant(sourceIdentifier, resolution.Strategy);
        }

        logger.NoStrategyResolvedTenant();
        return false;
    }
}
