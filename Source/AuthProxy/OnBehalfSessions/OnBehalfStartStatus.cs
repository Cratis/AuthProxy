// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Represents how an attempt to start an on-behalf session ended.
/// </summary>
public enum OnBehalfStartStatus
{
    /// <summary>
    /// The session started.
    /// </summary>
    Started = 0,

    /// <summary>
    /// On-behalf sessions are not configured.
    /// </summary>
    NotEnabled = 1,

    /// <summary>
    /// The caller is not signed in, or their identity cannot be forwarded.
    /// </summary>
    Unauthenticated = 2,

    /// <summary>
    /// The request is malformed, or names the caller themselves.
    /// </summary>
    Invalid = 3,

    /// <summary>
    /// The caller does not satisfy the configured actor requirements.
    /// </summary>
    Forbidden = 4,

    /// <summary>
    /// The caller already has an on-behalf session and must end it first.
    /// </summary>
    Conflict = 5,

    /// <summary>
    /// The application did not confirm a live grant.
    /// </summary>
    NotGranted = 6,

    /// <summary>
    /// The grant could not be confirmed, or the application did not acknowledge the start. Nothing was issued.
    /// </summary>
    Unavailable = 7,
}
