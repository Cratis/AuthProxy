// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.AccessTokens;

/// <summary>
/// Defines a system that obtains access tokens for a signed-in user, per audience.
/// </summary>
public interface IUserAccessTokens
{
    /// <summary>
    /// Gets an access token for the user's session and the audience a service declares.
    /// </summary>
    /// <param name="sessionId">The token session identifier carried by the user's session.</param>
    /// <param name="accessToken">The audience the service declares.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> for the operation.</param>
    /// <returns>The token, or why none could be obtained.</returns>
    Task<UserAccessTokenResult> GetFor(string sessionId, C.ServiceAccessToken accessToken, CancellationToken cancellationToken);
}
