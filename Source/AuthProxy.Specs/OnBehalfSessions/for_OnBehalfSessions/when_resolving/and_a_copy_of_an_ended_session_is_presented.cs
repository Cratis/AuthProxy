// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.when_resolving;

/// <summary>
/// A copied cookie of a session that already ended must not bring it back, and must not tell the application a second
/// time that it ended.
/// </summary>
public class and_a_copy_of_an_ended_session_is_presented : a_session_coordinator
{
    OnBehalfResolution _result;

    async Task Establish()
    {
        Carry(Sessions.At(_start));
        await _sessions.End(_context, OnBehalfSessionEndReason.EndedByActor);
    }

    async Task Because() => _result = await _sessions.Resolve(_context);

    [Fact] void should_still_be_ended() => _result.Status.ShouldEqual(OnBehalfResolutionStatus.Ended);
    [Fact] void should_say_how_it_ended() => _result.Reason.ShouldEqual(OnBehalfSessionEndReason.EndedByActor);
    [Fact] void should_not_ask_about_the_grant() => _grants.DidNotReceive().Check(Arg.Any<OnBehalfSession>(), Arg.Any<ClientPrincipal>(), Arg.Any<CancellationToken>());
    [Fact] void should_tell_the_application_only_once() => _notifier.Received(1).Ended(Arg.Any<OnBehalfSession>(), Arg.Any<OnBehalfSessionEndReason>(), Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>());
}
