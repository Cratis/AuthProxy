// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Scenarios.when_anonymous_paths_are_configured;

/// <summary>
/// The same host, but with a tenant-resolution strategy that cannot resolve anything for a caller with no
/// session — which is the only configuration in which <c>TenancyMiddleware</c>'s refusal branch is reached
/// at all.
/// <para>
/// This exists because the default factory resolves a fixed tenant for every request, so
/// <c>TenancyMiddleware</c> never gets to refuse and the scenario would stay green with that enforcement
/// point removed. An anonymous path only works if all three points agree, so each has to be able to fail
/// the suite on its own.
/// </para>
/// </summary>
public class UnresolvedTenantAuthProxyFactory : AuthProxyFactory
{
    /// <inheritdoc/>
    protected override IEnumerable<KeyValuePair<string, string?>> TenantResolutionSettings =>
    [
        new($"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy", nameof(C.TenantSourceIdentifierResolverType.Selection)),
    ];
}
