// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// Options for the <see cref="DefaultSourceIdentifierStrategy"/> that specifies the fallback tenant ID.
/// </summary>
public record DefaultOptions
{
    /// <summary>Gets the fallback tenant identifier.</summary>
    public string? TenantId { get; init; }
}
