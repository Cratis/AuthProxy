// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity;

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Defines the call to the application's grant check.
/// </summary>
public interface IOnBehalfGrants
{
    /// <summary>
    /// Asks the application whether the actor holds a live grant to act on behalf of the session's subject.
    /// </summary>
    /// <param name="session">The session asked about.</param>
    /// <param name="actor">The actor's own client principal.</param>
    /// <param name="cancellationToken">The caller's request lifetime.</param>
    /// <returns>The <see cref="OnBehalfGrant"/> the application stated. Never throws.</returns>
    Task<OnBehalfGrant> Check(OnBehalfSession session, ClientPrincipal actor, CancellationToken cancellationToken);
}
