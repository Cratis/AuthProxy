// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Maps one claim from the invite token to a claim in the principal
/// sent to the identity details provider.
/// </summary>
public class InviteClaimForwarding
{
    /// <summary>
    /// Gets or sets the claim type to read from the invite token.
    /// </summary>
    public string FromClaimType { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the claim type to emit in the outbound principal.
    /// When empty, <see cref="FromClaimType"/> is used.
    /// </summary>
    public string ToClaimType { get; set; } = string.Empty;
}
