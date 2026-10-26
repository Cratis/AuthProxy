// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.when_starting;

public class and_the_grant_cannot_be_confirmed : a_session_coordinator
{
    OnBehalfStartResult _result;

    void Establish() =>
        _grants.Check(Arg.Any<OnBehalfSession>(), Arg.Any<ClientPrincipal>(), Arg.Any<CancellationToken>()).Returns(OnBehalfGrant.Indeterminate);

    async Task Because() => _result = await _sessions.Start(_context, new(Sessions.Tenant, Sessions.Subject, Sessions.Issue));

    [Fact] void should_be_unavailable() => _result.Status.ShouldEqual(OnBehalfStartStatus.Unavailable);
    [Fact] void should_not_write_a_session_cookie() => SetCookie.ShouldEqual(string.Empty);
}
