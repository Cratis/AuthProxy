// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity;

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Represents the actor of an on-behalf session as the application is told about it.
/// </summary>
/// <param name="IdentityProvider">The identity provider the actor signed in with.</param>
/// <param name="UserId">The actor's subject.</param>
/// <param name="UserDetails">The actor's human-readable name or email.</param>
public sealed record OnBehalfActor(string IdentityProvider, string UserId, string UserDetails)
{
    /// <summary>
    /// Creates the actor from the actor's own client principal.
    /// </summary>
    /// <param name="principal">The actor's client principal.</param>
    /// <returns>The <see cref="OnBehalfActor"/>.</returns>
    public static OnBehalfActor From(ClientPrincipal principal) => new(principal.IdentityProvider, principal.UserId, principal.UserDetails);

    /// <summary>
    /// Determines whether a client principal is this actor.
    /// </summary>
    /// <param name="principal">The client principal of the caller on the current request.</param>
    /// <returns><see langword="true"/> when the identity provider and subject both match; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// Both are compared ordinally. A subject is only unique within its provider, so matching on the subject alone
    /// would let an account on another provider that happens to share it pick the session up.
    /// </remarks>
    public bool Is(ClientPrincipal? principal) =>
        principal is not null
        && !string.IsNullOrEmpty(principal.UserId)
        && string.Equals(principal.IdentityProvider, IdentityProvider, StringComparison.Ordinal)
        && string.Equals(principal.UserId, UserId, StringComparison.Ordinal);
}
