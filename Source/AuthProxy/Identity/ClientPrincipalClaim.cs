// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.Ingress.Identity;

/// <summary>
/// Represents a single claim entry within a <see cref="ClientPrincipal"/>,
/// matching the Microsoft Client Principal Data definition.
/// </summary>
public record ClientPrincipalClaim
{
    /// <summary>Gets or sets the claim type.</summary>
    [JsonPropertyName("typ")]
    public string Type { get; set; } = string.Empty;

    /// <summary>Gets or sets the claim value.</summary>
    [JsonPropertyName("val")]
    public string Value { get; set; } = string.Empty;
}
