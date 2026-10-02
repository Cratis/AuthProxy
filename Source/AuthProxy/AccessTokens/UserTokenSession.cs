// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens;

/// <summary>
/// Represents what AuthProxy keeps server-side for one signed-in session so it can obtain access tokens for the user.
/// </summary>
/// <param name="Scheme">The authentication scheme of the OIDC provider the user signed in with.</param>
/// <param name="RefreshToken">The refresh token the provider issued for the session.</param>
public sealed record UserTokenSession(string Scheme, string RefreshToken);
