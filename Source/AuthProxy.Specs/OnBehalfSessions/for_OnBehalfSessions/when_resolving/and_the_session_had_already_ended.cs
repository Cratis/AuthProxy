// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.when_resolving;

/// <summary>
/// The response refusing a request because its session ended also clears what the session left behind.
/// </summary>
public class and_the_session_had_already_ended : a_session_coordinator
{
    async Task Establish()
    {
        Carry(Sessions.At(_start));
        var elsewhere = new DefaultHttpContext { User = Sessions.ActorPrincipal() };
        elsewhere.Request.Headers.Cookie = _context.Request.Headers.Cookie;
        await _sessions.End(elsewhere, OnBehalfSessionEndReason.GrantNotLive);
    }

    async Task Because() => await _sessions.Resolve(_context);

    [Fact] void should_expire_the_identity_details_cookie() => SetCookie.ShouldContain($"{Cookies.Identity}=;");
    [Fact] void should_expire_the_authorization_record() => SetCookie.ShouldContain($"{Cookies.IdentityAuthorization}=;");
}
