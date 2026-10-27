// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Represents what the application's grant check established.
/// </summary>
public enum OnBehalfGrantStatus
{
    /// <summary>
    /// The application confirmed a live grant and identified the represented user.
    /// </summary>
    Live = 0,

    /// <summary>
    /// The application stated there is no live grant: it was never given, was revoked, or the session was ended.
    /// </summary>
    NotLive = 1,

    /// <summary>
    /// The application stated a grant whose <c language="text">validUntil</c> has already passed.
    /// </summary>
    Expired = 2,

    /// <summary>
    /// No verdict could be obtained: the call failed, timed out, or the answer did not follow the contract.
    /// Never treated as live.
    /// </summary>
    Indeterminate = 3,
}
