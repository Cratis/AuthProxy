// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfGrants.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfGrants.when_checking_a_grant;

/// <summary>
/// A quoted affirmative is not a verdict. Guessing whether somebody may act as another person from a string would be
/// the one guess this check exists to never make.
/// </summary>
public class and_the_verdict_is_not_a_boolean : a_grant_check
{
    protected override string? Body => LiveAnswer(live: "\"true\"");

    Task Because() => Check();

    [Fact] void should_be_indeterminate() => _result.Status.ShouldEqual(OnBehalfGrantStatus.Indeterminate);
}
