// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Defines the issuer of the signed tokens that authenticate AuthProxy to the application during on-behalf sessions.
/// </summary>
public interface IOnBehalfAttestations
{
    /// <summary>
    /// Issues the token for a call AuthProxy makes to the application: the grant check or a session notification.
    /// </summary>
    /// <param name="purpose">The <see cref="OnBehalfAttestationClaims.Purpose"/> of the call.</param>
    /// <param name="session">The session the call is about.</param>
    /// <param name="method">The HTTP method of the call.</param>
    /// <param name="target">The absolute target of the call.</param>
    /// <param name="body">The exact body bytes of the call; empty when it has none.</param>
    /// <param name="token">The signed token.</param>
    /// <returns><see langword="true"/> when a token was issued; otherwise <see langword="false"/>.</returns>
    bool TryIssueForCall(string purpose, OnBehalfSession session, HttpMethod method, Uri target, byte[] body, out string token);

    /// <summary>
    /// Issues the assertion forwarded with a request made during an on-behalf session.
    /// </summary>
    /// <param name="session">The session the request belongs to.</param>
    /// <param name="principalHeader">The exact <see cref="Headers.Principal"/> value forwarded: the represented user.</param>
    /// <param name="actorHeader">The exact <see cref="Headers.OnBehalfActor"/> value forwarded: the actor.</param>
    /// <param name="token">The signed assertion.</param>
    /// <returns><see langword="true"/> when an assertion was issued; otherwise <see langword="false"/>.</returns>
    bool TryIssueForForward(OnBehalfSession session, string principalHeader, string actorHeader, out string token);
}
