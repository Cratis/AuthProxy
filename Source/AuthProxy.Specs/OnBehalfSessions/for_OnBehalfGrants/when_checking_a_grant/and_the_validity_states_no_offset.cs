// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfGrants.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfGrants.when_checking_a_grant;

/// <summary>
/// A validity without an offset is a different instant on every machine that reads it. It is refused rather than read
/// in whatever time zone AuthProxy happens to run in.
/// </summary>
public class and_the_validity_states_no_offset : a_grant_check
{
    protected override string? Body => LiveAnswer(validUntil: "2026-09-01T13:00:00");

    Task Because() => Check();

    [Fact] void should_be_indeterminate() => _result.Status.ShouldEqual(OnBehalfGrantStatus.Indeterminate);
}
