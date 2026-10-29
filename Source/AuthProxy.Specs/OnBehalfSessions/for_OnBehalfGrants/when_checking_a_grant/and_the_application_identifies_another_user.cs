// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfGrants.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfGrants.when_checking_a_grant;

public class and_the_application_identifies_another_user : a_grant_check
{
    protected override string? Body => LiveAnswer(subject: "somebody-else");

    Task Because() => Check();

    [Fact] void should_be_indeterminate() => _result.Status.ShouldEqual(OnBehalfGrantStatus.Indeterminate);
    [Fact] void should_not_identify_anybody() => _result.Principal.ShouldBeNull();
}
