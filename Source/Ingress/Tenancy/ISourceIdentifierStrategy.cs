// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Ingress.Configuration;

namespace Cratis.Ingress.Tenancy;

#pragma warning disable MA0048 // File name must match type name
/// <summary>
/// Defines the contract for a single tenant source-identifier resolution strategy.
/// This interface is used to discover strategies by type and resolve tenant identifiers.
/// </summary>
public interface ISourceIdentifierStrategy
{
      /// <summary>Gets the strategy type this implementation handles.</summary>
    TenantSourceIdentifierResolverType Type { get; }
}

/// <summary>
/// Contract for a source identifier strategy with typed options.
/// </summary>
/// <typeparam name="TOptions">The typed options for this strategy.</typeparam>
public interface ISourceIdentifierStrategyTyped<TOptions> : ISourceIdentifierStrategy
{
      /// <summary>
        /// Tries to extract a source identifier string from the current request using typed options.
        /// </summary>
        /// <param name="context">Current HTTP context.</param>
        /// <param name="typedOptions">Strategy-specific typed options.</param>
        /// <param name="sourceIdentifier">The extracted source identifier, or empty string.</param>
        /// <returns><see langword="true"/> when a source identifier was extracted.</returns>
    bool TryResolveSourceIdentifier(HttpContext context, TOptions typedOptions, out string sourceIdentifier);
}
#pragma warning restore MA0048 // File name must match type name