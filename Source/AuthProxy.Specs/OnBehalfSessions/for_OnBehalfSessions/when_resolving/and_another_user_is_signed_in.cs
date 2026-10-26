// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.when_resolving;

public class and_another_user_is_signed_in : a_session_coordinator
{
    OnBehalfResolution _result;

    void Establish()
    {
        Carry(Sessions.At(_start));
        _context.User = Sessions.ActorPrincipal(subject: "someone-else");
    }

    async Task Because() => _result = await _sessions.Resolve(_context);

    [Fact] void should_proceed_as_whoever_is_signed_in() => _result.Status.ShouldEqual(OnBehalfResolutionStatus.None);
    [Fact] void should_tell_the_application_the_actor_changed() => _notifier.Received(1).Ended(Arg.Any<OnBehalfSession>(), OnBehalfSessionEndReason.ActorChanged, Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>());
    [Fact] void should_not_ask_about_the_grant() => _grants.DidNotReceive().Check(Arg.Any<OnBehalfSession>(), Arg.Any<ClientPrincipal>(), Arg.Any<CancellationToken>());
    [Fact] void should_remove_the_session_cookie() => SetCookie.ShouldContain($"{Cookies.OnBehalf}=;");
}
