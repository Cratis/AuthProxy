// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfGrants.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfGrants.when_checking_a_grant;

public class and_the_application_fails : a_grant_check
{
    protected override HttpStatusCode StatusCode => HttpStatusCode.InternalServerError;

    Task Because() => Check();

    [Fact] void should_be_indeterminate_rather_than_not_live() => _result.Status.ShouldEqual(OnBehalfGrantStatus.Indeterminate);
    [Fact] void should_never_be_live() => _result.IsLive.ShouldBeFalse();
}
