// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json.Nodes;
using Cratis.Ingress.Configuration;

namespace Cratis.Ingress.Tenancy;

/// <summary>
/// Defines the contract for a single tenant source-identifier resolution strategy.
/// </summary>
public interface ISourceIdentifierStrategy
{
    /// <summary>Gets the strategy type this implementation handles.</summary>
    TenantSourceIdentifierResolverType Type { get; }

    /// <summary>
    /// Tries to extract a source identifier string from the current request.
    /// The source identifier is then matched against the tenant map in <see cref="IngressConfig.Tenants"/>.
    /// </summary>
    /// <param name="context">Current HTTP context.</param>
    /// <param name="options">Strategy-specific options from configuration.</param>
    /// <param name="sourceIdentifier">The extracted source identifier, or empty string.</param>
    /// <returns><see langword="true"/> when a source identifier was extracted.</returns>
    bool TryResolveSourceIdentifier(HttpContext context, JsonObject options, out string sourceIdentifier);
}
