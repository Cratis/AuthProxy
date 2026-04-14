// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.Ingress.Configuration;

/// <summary>
/// Represents the configuration for a single tenant.
/// </summary>
public record TenantConfig
{
    /// <summary>
    /// Gets the display name of the tenant.
    /// </summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>
    /// Gets the domain name(s) that map to this tenant (used for host-based resolution).
    /// </summary>
    public IList<string> Domains { get; init; } = [];

    /// <summary>
    /// Gets source identifiers (e.g. claim values, route segments) that map to this tenant.
    /// </summary>
    public IList<string> SourceIdentifiers { get; init; } = [];
}
