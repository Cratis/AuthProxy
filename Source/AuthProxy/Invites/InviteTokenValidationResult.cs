// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Represents the result of validating an invite JWT token.
/// </summary>
public enum InviteTokenValidationResult
{
    /// <summary>The token is well-formed, properly signed, and not yet expired.</summary>
    Valid = 0,

    /// <summary>The token was well-formed and properly signed but has passed its expiry time.</summary>
    Expired = 1,

    /// <summary>The token is malformed, carries an invalid signature, or failed for any other reason.</summary>
    Invalid = 2,
}
