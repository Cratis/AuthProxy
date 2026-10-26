// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Represents why an on-behalf session ended. The wire value of each is given by <see cref="OnBehalfSessionEndReasons.ToWireValue"/>.
/// </summary>
public enum OnBehalfSessionEndReason
{
    /// <summary>
    /// The actor ended the session (<c language="text">ended-by-actor</c>).
    /// </summary>
    EndedByActor = 0,

    /// <summary>
    /// The grant check stated the grant is no longer live — revoked, or the session was ended by the application
    /// (<c language="text">grant-not-live</c>).
    /// </summary>
    GrantNotLive = 1,

    /// <summary>
    /// The grant's <c language="text">validUntil</c> passed (<c language="text">grant-expired</c>).
    /// </summary>
    GrantExpired = 2,

    /// <summary>
    /// The session reached the configured maximum lifetime (<c language="text">lifetime-exceeded</c>).
    /// </summary>
    LifetimeExceeded = 3,

    /// <summary>
    /// The actor's own session ended — signed out, expired or terminated (<c language="text">actor-session-ended</c>).
    /// </summary>
    ActorSessionEnded = 4,

    /// <summary>
    /// A different user signed in on the browser holding the session (<c language="text">actor-changed</c>).
    /// </summary>
    ActorChanged = 5,

    /// <summary>
    /// The application's identity endpoint refused the represented user in the tenant (<c language="text">represented-identity-denied</c>).
    /// </summary>
    RepresentedIdentityDenied = 6,

    /// <summary>
    /// The actor's browser entered an invitation, registration or account-link flow, which acts on the signed-in
    /// person's own account and never on the represented user's (<c language="text">identity-flow-started</c>).
    /// </summary>
    IdentityFlowStarted = 7,
}
