// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.when_resolving;

public class and_the_recheck_interval_has_passed : a_session_coordinator
{
    OnBehalfResolution _result;

    async Task Establish()
    {
        Carry(Sessions.At(_start));
        await _sessions.Resolve(_context);
        _time.Advance(C.OnBehalf.DefaultRecheckInterval);
        _grants.Check(Arg.Any<OnBehalfSession>(), Arg.Any<ClientPrincipal>(), Arg.Any<CancellationToken>()).Returns(OnBehalfGrant.NotLive);
    }

    async Task Because() => _result = await _sessions.Resolve(_context);

    [Fact] void should_ask_the_application_again() => _grants.Received(2).Check(Arg.Any<OnBehalfSession>(), Arg.Any<ClientPrincipal>(), Arg.Any<CancellationToken>());
    [Fact] void should_end_with_the_revoked_grant() => _result.Reason.ShouldEqual(OnBehalfSessionEndReason.GrantNotLive);
}
