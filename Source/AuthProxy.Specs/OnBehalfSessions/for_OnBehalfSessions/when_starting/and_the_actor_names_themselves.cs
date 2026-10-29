// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.when_starting;

public class and_the_actor_names_themselves : a_session_coordinator
{
    OnBehalfStartResult _result;

    async Task Because() => _result = await _sessions.Start(_context, new(Sessions.Tenant, Sessions.ActorSubject, Sessions.Issue));

    [Fact] void should_be_invalid() => _result.Status.ShouldEqual(OnBehalfStartStatus.Invalid);
}
