// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.Ingress.Tenancy;

/// <summary>
/// Options for the <see cref="SpecifiedSourceIdentifierStrategy"/> that specifies a tenant ID directly.
/// </summary>
public record SpecifiedOptions
{
        /// <summary>Gets the tenant identifier.</summary>
    public string? TenantId { get; init; }
}
