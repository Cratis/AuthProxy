// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Converts <see cref="OnBehalfSessionEndReason"/> to the value the application is sent.
/// </summary>
public static class OnBehalfSessionEndReasons
{
    /// <summary>
    /// Gets the wire value of a reason.
    /// </summary>
    /// <param name="reason">The reason.</param>
    /// <returns>The kebab-case value sent in the session-ended notification and the <see cref="Headers.OnBehalfEnded"/> header.</returns>
    public static string ToWireValue(this OnBehalfSessionEndReason reason) => reason switch
    {
        OnBehalfSessionEndReason.EndedByActor => "ended-by-actor",
        OnBehalfSessionEndReason.GrantNotLive => "grant-not-live",
        OnBehalfSessionEndReason.GrantExpired => "grant-expired",
        OnBehalfSessionEndReason.LifetimeExceeded => "lifetime-exceeded",
        OnBehalfSessionEndReason.ActorSessionEnded => "actor-session-ended",
        OnBehalfSessionEndReason.ActorChanged => "actor-changed",
        OnBehalfSessionEndReason.RepresentedIdentityDenied => "represented-identity-denied",
        OnBehalfSessionEndReason.IdentityFlowStarted => "identity-flow-started",
        _ => "ended",
    };
}
