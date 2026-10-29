// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.when_resolving;

public class and_the_grant_cannot_be_rechecked : a_session_coordinator
{
    OnBehalfResolution _result;

    void Establish()
    {
        Carry(Sessions.At(_start));
        _grants.Check(Arg.Any<OnBehalfSession>(), Arg.Any<ClientPrincipal>(), Arg.Any<CancellationToken>()).Returns(OnBehalfGrant.Indeterminate);
    }

    async Task Because() => _result = await _sessions.Resolve(_context);

    [Fact] void should_be_unavailable() => _result.Status.ShouldEqual(OnBehalfResolutionStatus.Unavailable);
    [Fact] void should_not_act_as_anybody() => _result.Context.ShouldBeNull();
    [Fact] void should_not_end_the_session() => _notifier.DidNotReceive().Ended(Arg.Any<OnBehalfSession>(), Arg.Any<OnBehalfSessionEndReason>(), Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>());
    [Fact] void should_keep_the_session_cookie() => SetCookie.ShouldEqual(string.Empty);
}
