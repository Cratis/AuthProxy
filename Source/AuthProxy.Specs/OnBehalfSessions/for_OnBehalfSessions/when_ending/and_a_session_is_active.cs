// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.when_ending;

/// <summary>
/// The identity details cookie and the sealed authorization record were written for the represented user. Neither may
/// outlive the session, or the frontend keeps showing the represented user to the actor.
/// </summary>
public class and_a_session_is_active : a_session_coordinator
{
    OnBehalfEndStatus _result;

    void Establish()
    {
        Carry(Sessions.At(_start));
        _context.Request.Headers.Cookie = $"{_context.Request.Headers.Cookie}; {Cookies.Identity}=represented; {Cookies.IdentityAuthorization}=sealed";
    }

    async Task Because() => _result = await _sessions.End(_context, OnBehalfSessionEndReason.EndedByActor);

    [Fact] void should_end() => _result.ShouldEqual(OnBehalfEndStatus.Ended);
    [Fact] void should_expire_the_session_cookie() => SetCookie.ShouldContain($"{Cookies.OnBehalf}=;");
    [Fact] void should_expire_the_identity_details_cookie() => SetCookie.ShouldContain($"{Cookies.Identity}=;");
    [Fact] void should_expire_the_authorization_record() => SetCookie.ShouldContain($"{Cookies.IdentityAuthorization}=;");
    [Fact] void should_tell_the_application() => _notifier.Received(1).Ended(Arg.Any<OnBehalfSession>(), OnBehalfSessionEndReason.EndedByActor, Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>());
}
