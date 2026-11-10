// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// The exact type name of a claim, matched ordinally.
/// </summary>
/// <param name="Value">The claim type name.</param>
readonly record struct ClaimType(string Value)
{
    /// <summary>
    /// Wraps a claim type name.
    /// </summary>
    /// <param name="value">The claim type name.</param>
    public static implicit operator ClaimType(string value) => new(value);
}
