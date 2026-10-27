// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.when_starting;

public class and_a_session_is_already_active : a_session_coordinator
{
    OnBehalfStartResult _result;

    void Establish() => Carry(Sessions.At(_start));

    async Task Because() => _result = await _sessions.Start(_context, new(Sessions.Tenant, "another-user", Sessions.Issue));

    [Fact] void should_conflict() => _result.Status.ShouldEqual(OnBehalfStartStatus.Conflict);
}
