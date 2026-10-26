// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.given;
using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfSessions.when_resolving;

public class and_the_grant_is_live : a_session_coordinator
{
    OnBehalfSession _session;
    OnBehalfResolution _result;

    void Establish()
    {
        _session = Sessions.At(_start);
        Carry(_session);
    }

    async Task Because() => _result = await _sessions.Resolve(_context);

    [Fact] void should_be_active() => _result.Status.ShouldEqual(OnBehalfResolutionStatus.Active);
    [Fact] void should_act_as_the_represented_user() => _result.Context!.Represented.UserId.ShouldEqual(Sessions.Subject);
    [Fact] void should_carry_the_session() => _result.Context!.Session.ShouldEqual(_session);
    [Fact] void should_forward_the_actors_subject() => (ClientPrincipal.TryFromBase64(_result.Context!.ActorHeader, out var actor) ? actor!.UserId : string.Empty).ShouldEqual(Sessions.ActorSubject);
    [Fact] void should_issue_signed_assertions_for_its_requests() => (_result.Context!.TryIssueAssertion(new(OnBehalfConfiguration.ServiceName, HttpMethod.Get, "/api"), "principal", out var assertion) && assertion.Length > 0).ShouldBeTrue();
}
