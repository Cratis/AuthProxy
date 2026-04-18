// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// Resolves the tenant ID from the request subhost by convention.
/// </summary>
public class SubHostSourceIdentifierStrategy : ISourceIdentifierStrategyTyped<SubHostOptions>
{
    /// <inheritdoc/>
    public C.TenantSourceIdentifierResolverType Type => C.TenantSourceIdentifierResolverType.SubHost;

    /// <inheritdoc/>
    public bool TryResolveSourceIdentifier(HttpContext context, SubHostOptions typedOptions, out string sourceIdentifier)
    {
        sourceIdentifier = string.Empty;

        var parentHost = typedOptions.ParentHost?.Trim().TrimStart('.');
        if (string.IsNullOrWhiteSpace(parentHost))
        {
            return false;
        }

        var host = context.Request.Host.Host;
        if (string.IsNullOrWhiteSpace(host))
        {
            return false;
        }

        var suffix = $".{parentHost}";
        if (!host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var subHost = host[..^suffix.Length];
        if (string.IsNullOrWhiteSpace(subHost) || subHost.Contains('.'))
        {
            return false;
        }

        sourceIdentifier = subHost;
        return true;
    }
}
