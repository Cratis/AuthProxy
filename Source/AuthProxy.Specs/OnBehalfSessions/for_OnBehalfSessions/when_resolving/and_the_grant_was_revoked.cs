// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.when_resolving;

public class and_the_grant_was_revoked : a_session_coordinator
{
    OnBehalfSession _session;
    OnBehalfResolution _result;

    void Establish()
    {
        _session = Sessions.At(_start);
        Carry(_session);
        _grants.Check(Arg.Any<OnBehalfSession>(), Arg.Any<ClientPrincipal>(), Arg.Any<CancellationToken>()).Returns(OnBehalfGrant.NotLive);
    }

    async Task Because() => _result = await _sessions.Resolve(_context);

    [Fact] void should_have_ended() => _result.Status.ShouldEqual(OnBehalfResolutionStatus.Ended);
    [Fact] void should_say_the_grant_is_gone() => _result.Reason.ShouldEqual(OnBehalfSessionEndReason.GrantNotLive);
    [Fact] void should_tell_the_application_it_ended() => _notifier.Received(1).Ended(_session, OnBehalfSessionEndReason.GrantNotLive, _start, Arg.Any<CancellationToken>());
    [Fact] void should_remove_the_session_cookie() => SetCookie.ShouldContain($"{Cookies.OnBehalf}=;");
}
