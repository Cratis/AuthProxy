// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfGrants.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfGrants.when_checking_a_grant;

public class and_the_grant_has_already_expired : a_grant_check
{
    protected override string? Body => LiveAnswer(validUntil: "2026-09-01T11:59:59Z");

    Task Because() => Check();

    [Fact] void should_have_expired() => _result.Status.ShouldEqual(OnBehalfGrantStatus.Expired);
}
