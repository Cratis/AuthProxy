// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Defines the protection of the on-behalf session cookie.
/// </summary>
public interface IOnBehalfSessionProtector
{
    /// <summary>
    /// Protects a session for the cookie.
    /// </summary>
    /// <param name="session">The <see cref="OnBehalfSession"/> to protect.</param>
    /// <returns>The protected value.</returns>
    string Protect(OnBehalfSession session);

    /// <summary>
    /// Recovers a session from a protected cookie value.
    /// </summary>
    /// <param name="protectedSession">The protected value.</param>
    /// <param name="session">The recovered <see cref="OnBehalfSession"/>.</param>
    /// <returns><see langword="true"/> when the value is an authentic, complete session; otherwise <see langword="false"/>.</returns>
    bool TryUnprotect(string protectedSession, out OnBehalfSession session);
}
