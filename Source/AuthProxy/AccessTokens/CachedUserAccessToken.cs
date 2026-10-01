// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens;

/// <summary>
/// Represents an access token held for a user and audience until shortly before it expires.
/// </summary>
/// <param name="Value">The access token.</param>
/// <param name="ExpiresAt">When the provider said the token expires.</param>
/// <param name="RenewAt">When the token must be renewed.</param>
public sealed record CachedUserAccessToken(string Value, DateTimeOffset ExpiresAt, DateTimeOffset RenewAt);
