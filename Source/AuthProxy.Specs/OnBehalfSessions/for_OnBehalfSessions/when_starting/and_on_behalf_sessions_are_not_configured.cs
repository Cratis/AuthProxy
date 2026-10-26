// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.when_starting;

public class and_on_behalf_sessions_are_not_configured : a_session_coordinator
{
    OnBehalfStartResult _result;

    void Establish() => _configuration.Value.OnBehalf = null;

    async Task Because() => _result = await _sessions.Start(_context, new(Sessions.Tenant, Sessions.Subject, Sessions.Issue));

    [Fact] void should_not_be_enabled() => _result.Status.ShouldEqual(OnBehalfStartStatus.NotEnabled);
}
