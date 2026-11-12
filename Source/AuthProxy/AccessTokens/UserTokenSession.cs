// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens;

/// <summary>
/// Represents what AuthProxy keeps server-side for one signed-in session so it can obtain access tokens for the user.
/// </summary>
/// <param name="Scheme">The authentication scheme of the OIDC provider the user signed in with.</param>
/// <param name="RefreshToken">The refresh token the provider issued for the session.</param>
public sealed record UserTokenSession(string Scheme, string RefreshToken)
{
    /// <summary>Gets the effective cookie lifetime for a provider override, or null to inherit the global policy.</summary>
    public TimeSpan? Lifetime { get; init; }

    /// <summary>Gets whether the issued cookie permits sliding retention, or null to inherit the global policy.</summary>
    public bool? Sliding { get; init; }

    /// <summary>Gets the fixed cookie deadline so storing its remaining session cannot extend it.</summary>
    internal DateTimeOffset? ExpiresAt { get; init; }
}
