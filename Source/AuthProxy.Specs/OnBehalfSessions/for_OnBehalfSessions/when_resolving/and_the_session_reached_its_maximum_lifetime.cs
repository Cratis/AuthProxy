// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.when_resolving;

public class and_the_session_reached_its_maximum_lifetime : a_session_coordinator
{
    OnBehalfResolution _result;

    void Establish()
    {
        Carry(Sessions.At(_start));
        _time.Advance(TimeSpan.FromHours(1));
    }

    async Task Because() => _result = await _sessions.Resolve(_context);

    [Fact] void should_have_ended() => _result.Reason.ShouldEqual(OnBehalfSessionEndReason.LifetimeExceeded);
    [Fact] void should_not_ask_about_the_grant() => _grants.DidNotReceive().Check(Arg.Any<OnBehalfSession>(), Arg.Any<ClientPrincipal>(), Arg.Any<CancellationToken>());
}
