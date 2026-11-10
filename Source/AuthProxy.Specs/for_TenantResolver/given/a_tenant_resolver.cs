// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenantResolver.given;

/// <summary>
/// Shared setup for specifications of the <see cref="TenantResolver"/>: a request context, a logger that
/// records every message, and helpers for building the configuration and the resolver.
/// </summary>
public class a_tenant_resolver : Specification
{
    protected Cratis.AuthProxy.given.RecordingLogger<TenantResolver> _logger;
    protected DefaultHttpContext _context;
    protected TenantResolver _resolver;
    protected bool _succeeded;
    protected TenantResolutionResult _result;

    protected bool UnusableIdentifierWasLogged => _logger.Messages.Any(_ => _.Contains("is not usable", StringComparison.Ordinal));

    protected bool NoStrategyResolvedWasLogged => _logger.Messages.Any(_ => _.Contains("could resolve a tenant", StringComparison.Ordinal));

    void Establish()
    {
        _logger = new();
        _context = new DefaultHttpContext();
        _result = new TenantResolutionResult(string.Empty, C.TenantSourceIdentifierResolverType.None);
    }

    protected static C.TenantResolution Resolution(C.TenantSourceIdentifierResolverType strategy, object? options = null) =>
        new() { Strategy = strategy, Options = options };

    protected static C.AuthProxy ConfigurationOf(params C.TenantResolution[] resolutions) =>
        new() { TenantResolutions = [.. resolutions] };

    protected static C.AuthProxy ConfigurationOf(C.Tenants tenants, params C.TenantResolution[] resolutions) =>
        new() { Tenants = tenants, TenantResolutions = [.. resolutions] };

    protected TenantResolver CreateResolver(C.AuthProxy config, params ISourceIdentifierStrategy[] strategies)
    {
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);
        return new TenantResolver(optionsMonitor, strategies, _logger);
    }
}
