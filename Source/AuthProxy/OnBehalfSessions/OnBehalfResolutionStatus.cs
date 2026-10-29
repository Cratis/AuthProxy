// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Represents what the on-behalf state of a request is.
/// </summary>
public enum OnBehalfResolutionStatus
{
    /// <summary>
    /// The request carries no usable on-behalf session and proceeds as the caller themselves.
    /// </summary>
    None = 0,

    /// <summary>
    /// The request acts on behalf of the represented user.
    /// </summary>
    Active = 1,

    /// <summary>
    /// The request's on-behalf session has ended. It must be refused, never forwarded as the actor instead.
    /// </summary>
    Ended = 2,

    /// <summary>
    /// The grant could not be re-checked. The request must be refused; the session is not ended.
    /// </summary>
    Unavailable = 3,
}
