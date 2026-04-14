// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;

using C = Cratis.Ingress.Configuration;
using T = Cratis.Ingress.Tenancy;
using Type = Cratis.Ingress.Configuration.TenantSourceIdentifierResolverType;

namespace Cratis.Ingress;

/// <summary>
/// Resolves the tenant ID by running the configured resolution strategies in order
/// until one succeeds, then matching the resulting source identifier against the
/// tenant map.
/// </summary>
/// <param name="config">The options monitor providing the current ingress configuration.</param>
/// <param name="strategies">The collection of available source identifier resolution strategies.</param>
/// <param name="logger">The logger.</param>
public class TenantResolver(
    IOptionsMonitor<C.IngressConfig> config,
    IEnumerable<T.ISourceIdentifierStrategy> strategies,
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

            // Claim strategy
            if (strategy is T.ISourceIdentifierStrategyTyped<T.ClaimOptions> claimStrategy)
            {
                var claimOptions = new T.ClaimOptions
                {
                    ClaimType = resolution.Options["claimType"]?.GetValue<string>()
                };

                if (!claimStrategy.TryResolveSourceIdentifier(context, claimOptions, out var sourceIdentifier))
                {
                    continue;
                }

                if (HandleResolvedSourceIdentifier(resolution.Strategy, sourceIdentifier, out tenantId, config.CurrentValue))
                {
                    return true;
                }
            }

            // Specified strategy
            else if (strategy is T.ISourceIdentifierStrategyTyped<T.SpecifiedOptions> specifiedStrategy)
            {
                var specifiedOptions = new T.SpecifiedOptions
                {
                    TenantId = resolution.Options["tenantId"]?.GetValue<string>()
                };

                if (!specifiedStrategy.TryResolveSourceIdentifier(context, specifiedOptions, out var sourceIdentifier))
                {
                    continue;
                }

                if (HandleResolvedSourceIdentifier(resolution.Strategy, sourceIdentifier, out tenantId, config.CurrentValue))
                {
                    return true;
                }
            }
            else if (strategy is T.ISourceIdentifierStrategyTyped<T.RouteOptions> routeStrategy)
            {
                var routeOptions = new T.RouteOptions
                {
                    Pattern = resolution.Options["pattern"]?.GetValue<string>()
                };

                if (!routeStrategy.TryResolveSourceIdentifier(context, routeOptions, out var sourceIdentifier))
                {
                    continue;
                }

                if (HandleResolvedSourceIdentifier(resolution.Strategy, sourceIdentifier, out tenantId, config.CurrentValue))
                {
                    return true;
                }
            }
            else if (strategy is T.ISourceIdentifierStrategyTyped<object>)
            {
                var sourceIdentifier = context.Request.Host.Host;
                if (string.IsNullOrEmpty(sourceIdentifier))
                {
                    continue;
                }

                if (HandleResolvedSourceIdentifier(resolution.Strategy, sourceIdentifier, out tenantId, config.CurrentValue))
                {
                    return true;
                }
            }
        }

        logger.NoStrategyResolvedTenant();
        return false;
    }

    private static bool HandleResolvedSourceIdentifier(
          Type strategyType,
          string sourceIdentifier,
          out Guid tenantId,
          C.IngressConfig config)
    {
        tenantId = Guid.Empty;

        // Specified strategy returns a fixed Guid directly.
        if (strategyType == Type.Specified
                 && Guid.TryParse(sourceIdentifier, out var specifiedId))
        {
            tenantId = specifiedId;
            return true;
        }

        // For all other strategies, look up the source identifier in the tenant map.
        foreach (var (id, tenantConfig) in config.Tenants)
        {
            if (tenantConfig.Domains.Contains(sourceIdentifier, StringComparer.OrdinalIgnoreCase)
                     || tenantConfig.SourceIdentifiers.Contains(sourceIdentifier, StringComparer.OrdinalIgnoreCase))
            {
                tenantId = id;
                return true;
            }
        }

        return false;
    }
}
