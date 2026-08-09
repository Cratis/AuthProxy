// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents a single claim a caller must carry to get past the proxy.
/// </summary>
/// <remarks>
/// A requirement is satisfied when the principal carries the named claim and — if <see cref="AnyOf"/>
/// lists any values — the claim's value is one of them. Listing several values is therefore an
/// <em>or</em>: "in any of these organizations". Requiring several claims (see
/// <see cref="Authorization.RequiredClaims"/>) is an <em>and</em>: every requirement has to hold.
/// <para>
/// Leaving <see cref="AnyOf"/> empty requires the claim to be <em>present</em>, whatever its value. That is
/// the right shape when the identity provider only emits the claim for the people who should get in.
/// </para>
/// </remarks>
public class ClaimRequirement
{
    /// <summary>
    /// Gets or sets the claim type that must be present on the authenticated principal, for example
    /// <c>urn:github:organization</c> or <c>roles</c>.
    /// </summary>
    public string Claim { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the values that satisfy the requirement. Leave empty to require only that the claim is
    /// present. Values are compared case-insensitively, after trimming surrounding whitespace.
    /// </summary>
    public IList<string> AnyOf { get; set; } = [];
}
