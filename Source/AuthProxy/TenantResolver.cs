// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;

using C = Cratis.AuthProxy.Configuration;
using T = Cratis.AuthProxy.Tenancy;
using Type = Cratis.AuthProxy.Configuration.TenantSourceIdentifierResolverType;

namespace Cratis.AuthProxy;

/// <summary>
/// Resolves the tenant ID by running the configured resolution strategies in order
/// until one succeeds, then matching the resulting source identifier against the
/// tenant map.
/// </summary>
/// <param name="config">The options monitor providing the current auth proxy configuration.</param>
/// <param name="strategies">The collection of available source identifier resolution strategies.</param>
/// <param name="logger">The logger.</param>
public class TenantResolver(
    IOptionsMonitor<C.AuthProxy> config,
    IEnumerable<T.ISourceIdentifierStrategy> strategies,
    ILogger<TenantResolver> logger) : ITenantResolver
{
    /// <inheritdoc/>
    public bool TryResolve(HttpContext context, out string tenantId)
    {
        tenantId = string.Empty;
        context.Items.Remove(TenancyMiddleware.TenantVerificationUrlTemplateItemKey);
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
                var claimOptions = resolution.Options as T.ClaimOptions ?? new T.ClaimOptions();

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
                var specifiedOptions = resolution.Options as T.SpecifiedOptions ?? new T.SpecifiedOptions();

                if (!specifiedStrategy.TryResolveSourceIdentifier(context, specifiedOptions, out var sourceIdentifier))
                {
                    continue;
                }

                if (HandleResolvedSourceIdentifier(resolution.Strategy, sourceIdentifier, out tenantId, config.CurrentValue))
                {
                    return true;
                }
            }

            // Default strategy
            else if (strategy is T.ISourceIdentifierStrategyTyped<T.DefaultOptions> defaultStrategy)
            {
                var defaultOptions = resolution.Options as T.DefaultOptions ?? new T.DefaultOptions();

                if (!defaultStrategy.TryResolveSourceIdentifier(context, defaultOptions, out var sourceIdentifier))
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
                var routeOptions = resolution.Options as T.RouteOptions ?? new T.RouteOptions();

                if (!routeStrategy.TryResolveSourceIdentifier(context, routeOptions, out var sourceIdentifier))
                {
                    continue;
                }

                if (HandleResolvedSourceIdentifier(resolution.Strategy, sourceIdentifier, out tenantId, config.CurrentValue))
                {
                    return true;
                }
            }
            else if (strategy is T.ISourceIdentifierStrategyTyped<T.SubHostOptions> subHostStrategy)
            {
                var subHostOptions = resolution.Options as T.SubHostOptions ?? new T.SubHostOptions();

                if (!subHostStrategy.TryResolveSourceIdentifier(context, subHostOptions, out var sourceIdentifier))
                {
                    continue;
                }

                if (HandleResolvedSourceIdentifier(resolution.Strategy, sourceIdentifier, out tenantId, config.CurrentValue))
                {
                    if (!string.IsNullOrWhiteSpace(subHostOptions.VerificationUrlTemplate))
                    {
                        context.Items[TenancyMiddleware.TenantVerificationUrlTemplateItemKey] = subHostOptions.VerificationUrlTemplate;
                    }

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
          out string tenantId,
          C.AuthProxy config)
    {
        tenantId = string.Empty;

        // Specified, Default, and SubHost strategies return a fixed tenant ID directly.
        if (strategyType == Type.Specified || strategyType == Type.Default || strategyType == Type.SubHost)
        {
            if (!string.IsNullOrWhiteSpace(sourceIdentifier))
            {
                tenantId = sourceIdentifier;
                return true;
            }

            return false;
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
