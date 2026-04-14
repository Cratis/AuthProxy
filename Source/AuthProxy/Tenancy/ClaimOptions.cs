// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// Options for the <see cref="ClaimSourceIdentifierStrategy"/> that resolves tenant ID from a claim.
/// </summary>
public record ClaimOptions
{
    /// <summary>Gets the claim type to use for resolving the tenant identifier. Defaults to the Microsoft standard tenant claim.</summary>
    public string? ClaimType { get; init; }
}
