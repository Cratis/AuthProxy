// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents a single tenant resolution strategy configuration.
/// </summary>
public class TenantResolution
{
    /// <summary>
    /// Gets or sets the strategy type to use for resolving the tenant source identifier.
    /// </summary>
    public TenantSourceIdentifierResolverType Strategy { get; set; } = TenantSourceIdentifierResolverType.None;

    /// <summary>
    /// Gets or sets the strategy-specific options (e.g. claim type, regex pattern, fixed tenant ID).
    /// Populated at startup by <c>TenantResolutionOptionsConfigurer</c> which binds the configuration
    /// sub-section to the concrete typed options class that matches <see cref="Strategy"/>.
    /// </summary>
    public object? Options { get; set; }
}
