// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfGrants.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfGrants.when_checking_a_grant;

public class and_the_validity_states_an_explicit_offset : a_grant_check
{
    protected override string? Body => LiveAnswer(validUntil: "2026-09-01T15:00:00+02:00");

    Task Because() => Check();

    [Fact] void should_be_live() => _result.IsLive.ShouldBeTrue();
    [Fact] void should_read_the_instant_it_states() => _result.ValidUntil.ShouldEqual(_now.AddHours(1));
}
