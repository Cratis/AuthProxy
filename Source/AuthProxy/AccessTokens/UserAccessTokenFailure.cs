// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens;

/// <summary>
/// Defines why no access token could be obtained for the signed-in user.
/// </summary>
public enum UserAccessTokenFailure
{
    /// <summary>
    /// A token was obtained.
    /// </summary>
    None = 0,

    /// <summary>
    /// The session has no refresh token held for it: the provider issued none (no <c language="text">offline_access</c>),
    /// the session began before token forwarding was configured, or another AuthProxy instance holds it.
    /// </summary>
    NoRefreshToken = 1,

    /// <summary>
    /// The user signed in with a provider other than the one the service names.
    /// </summary>
    WrongProvider = 2,

    /// <summary>
    /// The provider refused the refresh token; the user has to sign in again.
    /// </summary>
    RefreshTokenRejected = 3,

    /// <summary>
    /// The provider could not be reached or answered with something other than a bearer token.
    /// </summary>
    ProviderUnavailable = 4,
}
