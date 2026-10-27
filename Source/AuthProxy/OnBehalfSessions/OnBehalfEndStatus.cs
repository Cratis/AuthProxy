// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Represents how ending a session went.
/// </summary>
public enum OnBehalfEndStatus
{
    /// <summary>
    /// There was no session to end.
    /// </summary>
    NoSession = 0,

    /// <summary>
    /// The session ended and the application acknowledged it, or it had already ended.
    /// </summary>
    Ended = 1,

    /// <summary>
    /// The session ended, but the application did not acknowledge the notification.
    /// </summary>
    EndedWithoutNotification = 2,
}
