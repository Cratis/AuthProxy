// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Represents the on-behalf state of a request.
/// </summary>
/// <param name="Status">The state.</param>
/// <param name="Context">The active session, when <see cref="OnBehalfResolutionStatus.Active"/>.</param>
/// <param name="Reason">Why the session ended, when <see cref="OnBehalfResolutionStatus.Ended"/>.</param>
public sealed record OnBehalfResolution(OnBehalfResolutionStatus Status, OnBehalfContext? Context = null, OnBehalfSessionEndReason? Reason = null)
{
    /// <summary>
    /// Gets the state of a request without a usable session.
    /// </summary>
    public static OnBehalfResolution None { get; } = new(OnBehalfResolutionStatus.None);

    /// <summary>
    /// Gets the state of a request whose grant could not be re-checked.
    /// </summary>
    public static OnBehalfResolution Unavailable { get; } = new(OnBehalfResolutionStatus.Unavailable);
}
