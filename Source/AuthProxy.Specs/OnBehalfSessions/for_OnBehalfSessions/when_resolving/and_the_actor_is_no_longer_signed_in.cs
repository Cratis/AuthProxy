// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.when_resolving;

public class and_the_actor_is_no_longer_signed_in : a_session_coordinator
{
    OnBehalfResolution _result;

    void Establish()
    {
        Carry(Sessions.At(_start));
        _context.User = new ClaimsPrincipal(new ClaimsIdentity());
    }

    async Task Because() => _result = await _sessions.Resolve(_context);

    [Fact] void should_not_act_as_anybody() => _result.Status.ShouldEqual(OnBehalfResolutionStatus.None);
    [Fact] void should_tell_the_application_the_actor_session_ended() => _notifier.Received(1).Ended(Arg.Any<OnBehalfSession>(), OnBehalfSessionEndReason.ActorSessionEnded, Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>());
}
