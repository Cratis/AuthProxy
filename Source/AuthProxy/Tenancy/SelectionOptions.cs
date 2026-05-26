// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// Options for the <see cref="SelectionSourceIdentifierStrategy"/>.
/// </summary>
public record SelectionOptions
{
    /// <summary>
    /// Gets the endpoint URL that returns the selectable tenant list for the authenticated user.
    /// </summary>
    public string TenantsEndpoint { get; init; } = string.Empty;
}
