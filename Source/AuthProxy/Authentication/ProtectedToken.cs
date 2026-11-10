// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// The protected text of an AuthProxy-issued bearer token, exactly as presented by a caller.
/// </summary>
/// <param name="Value">The protected token text.</param>
readonly record struct ProtectedToken(string Value)
{
    /// <summary>
    /// Wraps protected token text.
    /// </summary>
    /// <param name="value">The protected token text.</param>
    public static implicit operator ProtectedToken(string value) => new(value);
}
