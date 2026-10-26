// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Defines the notifications that tell the application an on-behalf session started or ended.
/// </summary>
public interface IOnBehalfSessionNotifier
{
    /// <summary>
    /// Tells the application a session started.
    /// </summary>
    /// <param name="session">The session that started.</param>
    /// <param name="grant">The live grant it started under.</param>
    /// <param name="cancellationToken">The caller's request lifetime.</param>
    /// <returns><see langword="true"/> when the application acknowledged it with a success status; otherwise <see langword="false"/>. Never throws.</returns>
    Task<bool> Started(OnBehalfSession session, OnBehalfGrant grant, CancellationToken cancellationToken);

    /// <summary>
    /// Tells the application a session ended.
    /// </summary>
    /// <param name="session">The session that ended.</param>
    /// <param name="reason">Why it ended.</param>
    /// <param name="endedAt">When it ended.</param>
    /// <param name="cancellationToken">The caller's request lifetime.</param>
    /// <returns><see langword="true"/> when the application acknowledged it with a success status; otherwise <see langword="false"/>. Never throws.</returns>
    Task<bool> Ended(OnBehalfSession session, OnBehalfSessionEndReason reason, DateTimeOffset endedAt, CancellationToken cancellationToken);
}
