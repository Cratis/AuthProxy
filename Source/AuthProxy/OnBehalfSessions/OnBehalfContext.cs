// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity;

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Represents an on-behalf session that is active on the current request.
/// </summary>
/// <param name="Session">The session.</param>
/// <param name="Represented">The represented user, as the application identified them in its latest grant answer.</param>
/// <param name="ActorHeader">The exact <see cref="Headers.OnBehalfActor"/> value to forward.</param>
/// <param name="Assertion">The signed <see cref="Headers.OnBehalfAssertion"/> to forward.</param>
public sealed record OnBehalfContext(
    OnBehalfSession Session,
    ClientPrincipal Represented,
    string ActorHeader,
    string Assertion);
