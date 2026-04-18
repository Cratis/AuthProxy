// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// Always resolves to the tenant ID configured in <see cref="DefaultOptions.TenantId"/>.
/// Used as a fallback tenant when no other strategy produces a match — for example, the
/// Lobby's well-known default tenant that receives new users during invite onboarding.
/// </summary>
public class DefaultSourceIdentifierStrategy : ISourceIdentifierStrategyTyped<DefaultOptions>
{
    /// <inheritdoc/>
    public C.TenantSourceIdentifierResolverType Type => C.TenantSourceIdentifierResolverType.Default;

    /// <inheritdoc/>
    public bool TryResolveSourceIdentifier(HttpContext context, DefaultOptions typedOptions, out string sourceIdentifier)
    {
        sourceIdentifier = typedOptions.TenantId ?? string.Empty;
        return !string.IsNullOrEmpty(sourceIdentifier);
    }
}
