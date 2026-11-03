// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// The tokens issued for a successful grant.
/// </summary>
/// <param name="AccessToken">The protected access token.</param>
/// <param name="ExpiresInSeconds">The number of whole seconds the access token stays valid.</param>
/// <param name="RefreshToken">The protected refresh token.</param>
public record ClientCredentialsIssuedTokens(
    string AccessToken,
    int ExpiresInSeconds,
    string RefreshToken);
