// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.Ingress.Configuration;

/// <summary>
/// Represents a single tenant resolution strategy configuration.
/// </summary>
public class TenantResolutionConfig
{
    /// <summary>
    /// Gets or sets the strategy type to use for resolving the tenant source identifier.
    /// </summary>
    public TenantSourceIdentifierResolverType Strategy { get; set; } = TenantSourceIdentifierResolverType.None;

    /// <summary>
    /// Gets or sets the strategy-specific options (e.g. claim type, regex pattern, fixed tenant ID).
    /// </summary>
    public System.Text.Json.Nodes.JsonObject Options { get; set; } = [];
}
