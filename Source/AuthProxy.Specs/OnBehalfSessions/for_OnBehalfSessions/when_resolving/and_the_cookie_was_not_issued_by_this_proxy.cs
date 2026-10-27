// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.when_resolving;

public class and_the_cookie_was_not_issued_by_this_proxy : a_session_coordinator
{
    OnBehalfResolution _result;

    void Establish() => _context.Request.Headers.Cookie = $"{Cookies.OnBehalf}=forged";

    async Task Because() => _result = await _sessions.Resolve(_context);

    [Fact] void should_not_act_as_anybody() => _result.Status.ShouldEqual(OnBehalfResolutionStatus.None);
    [Fact] void should_not_ask_about_any_grant() => _grants.DidNotReceive().Check(Arg.Any<OnBehalfSession>(), Arg.Any<ClientPrincipal>(), Arg.Any<CancellationToken>());
    [Fact] void should_remove_the_cookie() => SetCookie.ShouldContain($"{Cookies.OnBehalf}=;");
}
