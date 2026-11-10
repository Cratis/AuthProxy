// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Telemetry;
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
        var resolved = TryResolve(context, out TenantResolutionResult result);
        tenantId = result.TenantId;
        return resolved;
    }

    /// <inheritdoc/>
    public bool TryResolve(HttpContext context, out TenantResolutionResult result)
    {
        using var activity = AuthProxyTelemetry.Start(WellKnownTelemetryNames.TenantResolveSpan);
        result = new TenantResolutionResult(string.Empty, Type.None);
        context.Items.Remove(TenancyMiddleware.TenantVerificationUrlTemplateItemKey);
        var current = config.CurrentValue;

        if (current.TenantResolutions.Count == 0)
        {
            // No resolution configured – treat as single-tenant with empty tenant ID.
            AuthProxyTelemetry.TenantResolved(activity, true, result.Strategy);
            return true;
        }

        foreach (var resolution in current.TenantResolutions)
        {
            if (TryResolveWith(context, resolution, current, out result))
            {
                AuthProxyTelemetry.TenantResolved(activity, true, result.Strategy);
                return true;
            }
        }

        result = new TenantResolutionResult(string.Empty, Type.None);
        logger.NoStrategyResolvedTenant();
        AuthProxyTelemetry.TenantResolved(activity, false, result.Strategy);
        return false;
    }

    /// <inheritdoc/>
    public IEnumerable<TenantResolutionResult> ResolveEach(HttpContext context)
    {
        context.Items.Remove(TenancyMiddleware.TenantVerificationUrlTemplateItemKey);
        var current = config.CurrentValue;
        var results = new List<TenantResolutionResult>();
        foreach (var resolution in current.TenantResolutions)
        {
            if (TryResolveWith(context, resolution, current, out var result))
            {
                results.Add(result);
            }
        }

        return results;
    }

    static bool TryMatchTenant(string sourceIdentifier, C.AuthProxy config, out string tenantId)
    {
        tenantId = string.Empty;

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

    static TenantResolutionResult CreateResult(HttpContext context, Type strategy, string tenantId, object options)
    {
        if (options is not T.SubHostOptions subHostOptions)
        {
            return new TenantResolutionResult(tenantId, strategy);
        }

        if (!string.IsNullOrWhiteSpace(subHostOptions.VerificationUrlTemplate))
        {
            context.Items[TenancyMiddleware.TenantVerificationUrlTemplateItemKey] = subHostOptions.VerificationUrlTemplate;
        }

        return new TenantResolutionResult(tenantId, strategy, subHostOptions.ParentHost);
    }

    static bool IsNonBlankButUnusable(Type strategyType, string sourceIdentifier) =>
        strategyType is Type.Route or Type.Claim
        && !string.IsNullOrWhiteSpace(sourceIdentifier)
        && !T.TenantIdentifier.IsUsable(sourceIdentifier);

    static bool ResolvesDirectlyToTenantId(Type strategyType) =>
        strategyType is Type.Specified or Type.Default or Type.SubHost or Type.Selection;

    bool HandleResolvedSourceIdentifier(
          Type strategyType,
          string sourceIdentifier,
          out string tenantId,
          C.AuthProxy config)
    {
        if (HandleKnownSourceIdentifier(strategyType, sourceIdentifier, out tenantId, config)
            && !T.TenantIdentifier.IsUsable(tenantId))
        {
            logger.UnusableTenantIdentifier(strategyType);
            tenantId = string.Empty;
            return false;
        }

        return !string.IsNullOrEmpty(tenantId);
    }

    bool HandleKnownSourceIdentifier(
          Type strategyType,
          string sourceIdentifier,
          out string tenantId,
          C.AuthProxy config)
    {
        tenantId = string.Empty;

        if (IsNonBlankButUnusable(strategyType, sourceIdentifier))
        {
            logger.UnusableTenantIdentifier(strategyType);
            return false;
        }

        // Specified, Default, and SubHost strategies return a fixed tenant ID directly.
        if (ResolvesDirectlyToTenantId(strategyType))
        {
            if (!string.IsNullOrWhiteSpace(sourceIdentifier))
            {
                tenantId = sourceIdentifier;
                return true;
            }

            return false;
        }

        return TryMatchTenant(sourceIdentifier, config, out tenantId);
    }

    bool TryResolveWith(HttpContext context, C.TenantResolution resolution, C.AuthProxy current, out TenantResolutionResult result)
    {
        result = new TenantResolutionResult(string.Empty, Type.None);
        var strategy = strategies.FirstOrDefault(s => s.Type == resolution.Strategy);
        var request = new ResolutionRequest(context, resolution, current);
        return strategy switch
        {
            T.ISourceIdentifierStrategyTyped<T.ClaimOptions> typed => TryResolveTyped(in request, typed, out result),
            T.ISourceIdentifierStrategyTyped<T.SpecifiedOptions> typed => TryResolveTyped(in request, typed, out result),
            T.ISourceIdentifierStrategyTyped<T.DefaultOptions> typed => TryResolveTyped(in request, typed, out result),
            _ => TryResolveFromRequest(strategy, in request, out result)
        };
    }

    bool TryResolveFromRequest(T.ISourceIdentifierStrategy? strategy, in ResolutionRequest request, out TenantResolutionResult result)
    {
        result = new TenantResolutionResult(string.Empty, Type.None);
        return strategy switch
        {
            T.ISourceIdentifierStrategyTyped<T.SelectionOptions> typed => TryResolveTyped(in request, typed, out result),
            T.ISourceIdentifierStrategyTyped<T.RouteOptions> typed => TryResolveTyped(in request, typed, out result),
            T.ISourceIdentifierStrategyTyped<T.SubHostOptions> typed => TryResolveTyped(in request, typed, out result),
            T.ISourceIdentifierStrategyTyped<object> => TryResolveHost(in request, out result),
            _ => false
        };
    }

    bool TryResolveTyped<TOptions>(
        in ResolutionRequest request,
        T.ISourceIdentifierStrategyTyped<TOptions> strategy,
        out TenantResolutionResult result)
        where TOptions : class, new()
    {
        result = new TenantResolutionResult(string.Empty, Type.None);
        var (context, resolution, current) = request;
        var options = resolution.Options as TOptions ?? new TOptions();
        if (!strategy.TryResolveSourceIdentifier(context, options, out var sourceIdentifier))
        {
            return false;
        }

        if (!HandleResolvedSourceIdentifier(resolution.Strategy, sourceIdentifier, out var tenantId, current))
        {
            return false;
        }

        result = CreateResult(context, resolution.Strategy, tenantId, options);
        return true;
    }

    bool TryResolveHost(in ResolutionRequest request, out TenantResolutionResult result)
    {
        result = new TenantResolutionResult(string.Empty, Type.None);
        var (context, resolution, current) = request;
        var sourceIdentifier = context.Request.Host.Host;
        if (string.IsNullOrEmpty(sourceIdentifier))
        {
            return false;
        }

        if (!HandleResolvedSourceIdentifier(resolution.Strategy, sourceIdentifier, out var tenantId, current))
        {
            return false;
        }

        result = new TenantResolutionResult(tenantId, resolution.Strategy);
        return true;
    }

    readonly record struct ResolutionRequest(HttpContext Context, C.TenantResolution Resolution, C.AuthProxy Current);
}
