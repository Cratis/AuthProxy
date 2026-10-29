// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.when_starting;

/// <summary>
/// A session another actor left behind on a shared browser does not block this actor. It ends — and the application
/// hears so — before this actor's own session starts.
/// </summary>
public class and_another_actors_session_is_left_on_the_browser : a_session_coordinator
{
    OnBehalfSession _leftover;
    OnBehalfStartResult _result;

    void Establish()
    {
        _leftover = Sessions.At(_start, "leftover") with { Actor = new OnBehalfActor(Sessions.ActorProvider, "somebody-else", "else@example.com") };
        Carry(_leftover);
    }

    async Task Because() => _result = await _sessions.Start(_context, new(Sessions.Tenant, Sessions.Subject, Sessions.Issue));

    [Fact] void should_start() => _result.Status.ShouldEqual(OnBehalfStartStatus.Started);
    [Fact] void should_end_the_leftover_session() => _ledger.HasEnded(_leftover.SessionId, out _).ShouldBeTrue();
    [Fact] void should_tell_the_application_the_leftover_session_ended() => _notifier.Received(1).Ended(_leftover, OnBehalfSessionEndReason.ActorChanged, Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>());
}
