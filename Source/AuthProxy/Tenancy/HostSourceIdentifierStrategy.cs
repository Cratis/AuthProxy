// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// Resolves the tenant source identifier from the HTTP request host name.
/// </summary>
public class HostSourceIdentifierStrategy : ISourceIdentifierStrategyTyped<object>
{
    /// <inheritdoc/>
    public C.TenantSourceIdentifierResolverType Type => C.TenantSourceIdentifierResolverType.Host;

    /// <inheritdoc/>
    public bool TryResolveSourceIdentifier(HttpContext context, object typedOptions, out string sourceIdentifier)
    {
        sourceIdentifier = context.Request.Host.Host;
        return !string.IsNullOrEmpty(sourceIdentifier);
    }
}
