// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.when_starting;

public class and_the_actor_is_not_support : a_session_coordinator
{
    OnBehalfStartResult _result;

    void Establish() => _context.User = Sessions.ActorPrincipal(support: false);

    async Task Because() => _result = await _sessions.Start(_context, new(Sessions.Tenant, Sessions.Subject, Sessions.Issue));

    [Fact] void should_be_forbidden() => _result.Status.ShouldEqual(OnBehalfStartStatus.Forbidden);
    [Fact] void should_not_even_ask_the_application() => _grants.DidNotReceive().Check(Arg.Any<OnBehalfSession>(), Arg.Any<ClientPrincipal>(), Arg.Any<CancellationToken>());
}
