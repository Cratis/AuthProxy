// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Represents the actor in a session notification.
/// </summary>
/// <param name="IdentityProvider">The identity provider the actor signed in with.</param>
/// <param name="UserId">The actor's subject.</param>
/// <param name="UserDetails">The actor's human-readable name or email.</param>
public sealed record OnBehalfActorNotification(
    [property: JsonPropertyName("identityProvider")] string IdentityProvider,
    [property: JsonPropertyName("userId")] string UserId,
    [property: JsonPropertyName("userDetails")] string UserDetails)
{
    /// <summary>
    /// Creates the notification shape of an actor.
    /// </summary>
    /// <param name="actor">The actor.</param>
    /// <returns>The <see cref="OnBehalfActorNotification"/>.</returns>
    public static OnBehalfActorNotification From(OnBehalfActor actor) => new(actor.IdentityProvider, actor.UserId, actor.UserDetails);
}
