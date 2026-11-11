// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens;

/// <summary>
/// Identifies the audience a session holds a token for.
/// </summary>
/// <param name="SessionId">The session identifier.</param>
/// <param name="Audience">The audience key.</param>
public readonly record struct UserTokenAudience(string SessionId, string Audience);
