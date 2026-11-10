// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenantResolver.given;

/// <summary>
/// A strategy of a chosen type that always produces the same source identifier.
/// </summary>
/// <param name="type">The strategy type this instance claims to handle.</param>
/// <param name="identifier">The source identifier it always produces.</param>
public class FixedIdentifierStrategy(C.TenantSourceIdentifierResolverType type, string identifier) : ISourceIdentifierStrategyTyped<SpecifiedOptions>
{
    /// <inheritdoc/>
    public C.TenantSourceIdentifierResolverType Type => type;

    /// <inheritdoc/>
    public bool TryResolveSourceIdentifier(HttpContext context, SpecifiedOptions typedOptions, out string sourceIdentifier)
    {
        sourceIdentifier = identifier;
        return true;
    }
}
