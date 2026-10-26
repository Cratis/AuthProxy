// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity;

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Represents an active on-behalf session on the request it was resolved for.
/// </summary>
/// <param name="Session">The session.</param>
/// <param name="Represented">The represented user, as the application's grant check identified them.</param>
/// <param name="ActorHeader">The <see cref="Headers.OnBehalfActor"/> value: the actor as a base64 client principal.</param>
/// <param name="Attestations">The issuer of the assertion forwarded with every request the session sends.</param>
public sealed record OnBehalfContext(
    OnBehalfSession Session,
    ClientPrincipal Represented,
    string ActorHeader,
    IOnBehalfAttestations Attestations)
{
    /// <summary>
    /// Issues the <see cref="Headers.OnBehalfAssertion"/> for one request the session sends.
    /// </summary>
    /// <param name="forward">The request the assertion is for.</param>
    /// <param name="principalHeader">The exact <see cref="Headers.Principal"/> value the request carries.</param>
    /// <param name="assertion">The signed assertion.</param>
    /// <returns><see langword="true"/> when the assertion was issued; otherwise <see langword="false"/>.</returns>
    public bool TryIssueAssertion(OnBehalfForward forward, string principalHeader, out string assertion) =>
        Attestations.TryIssueForForward(Session, forward, principalHeader, ActorHeader, out assertion);
}
