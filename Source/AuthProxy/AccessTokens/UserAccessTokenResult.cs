// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens;

/// <summary>
/// Represents the outcome of obtaining an access token for the signed-in user.
/// </summary>
/// <param name="Token">The access token, when one was obtained.</param>
/// <param name="Failure">Why no token was obtained, or <see cref="UserAccessTokenFailure.None"/>.</param>
public sealed record UserAccessTokenResult(string? Token, UserAccessTokenFailure Failure)
{
    /// <summary>
    /// Gets a value indicating whether a token was obtained.
    /// </summary>
    public bool Succeeded => Failure == UserAccessTokenFailure.None && Token is not null;

    /// <summary>
    /// Creates a successful result.
    /// </summary>
    /// <param name="token">The access token.</param>
    /// <returns>The result.</returns>
    public static UserAccessTokenResult Success(string token) => new(token, UserAccessTokenFailure.None);

    /// <summary>
    /// Creates a failed result.
    /// </summary>
    /// <param name="failure">Why no token was obtained.</param>
    /// <returns>The result.</returns>
    public static UserAccessTokenResult Failed(UserAccessTokenFailure failure) => new(null, failure);
}
