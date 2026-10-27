// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.when_starting;

public class and_the_grant_is_live : a_session_coordinator
{
    OnBehalfStartResult _result;

    async Task Because() => _result = await _sessions.Start(_context, new(Sessions.Tenant, Sessions.Subject, Sessions.Issue));

    [Fact] void should_start() => _result.Status.ShouldEqual(OnBehalfStartStatus.Started);
    [Fact] void should_act_for_the_requested_subject() => _result.Session!.Subject.ShouldEqual(Sessions.Subject);
    [Fact] void should_act_in_the_requested_tenant() => _result.Session!.Tenant.ShouldEqual(Sessions.Tenant);
    [Fact] void should_record_the_actor() => _result.Session!.Actor.ShouldEqual(Sessions.Actor);
    [Fact] void should_end_at_the_maximum_lifetime_at_the_latest() => _result.Session!.ExpiresAt.ShouldEqual(_start.Add(C.OnBehalf.DefaultMaximumLifetime));
    [Fact] void should_check_the_grant_for_the_actor() => _grants.Received(1).Check(Arg.Any<OnBehalfSession>(), Arg.Is<ClientPrincipal>(_ => _.UserId == Sessions.ActorSubject), Arg.Any<CancellationToken>());
    [Fact] void should_tell_the_application_it_started() => _notifier.Received(1).Started(_result.Session!, Arg.Any<OnBehalfGrant>(), Arg.Any<CancellationToken>());
    [Fact] void should_write_the_session_cookie() => SetCookie.ShouldContain($"{Cookies.OnBehalf}=");
    [Fact] void should_keep_the_cookie_from_script() => SetCookie.ShouldContain("httponly");
}
