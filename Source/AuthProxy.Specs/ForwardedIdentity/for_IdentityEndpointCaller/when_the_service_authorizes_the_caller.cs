// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.ForwardedIdentity.for_IdentityEndpointCaller;

public class when_the_service_authorizes_the_caller : given.a_caller_answered_by_the_service
{
    protected override Task<HttpResponseMessage> Respond(CancellationToken cancellationToken) =>
        Task.FromResult(Json(HttpStatusCode.OK, """{"IsAuthorized":true,"details":{"name":"n"}}"""));

    async Task Because() => _outcome = await Call(CancellationToken.None);

    [Fact] void should_be_positive() => _outcome.Status.ShouldEqual(IdentityVerificationStatus.Positive);
    [Fact] void should_carry_the_details() => _outcome.Details["name"]!.GetValue<string>().ShouldEqual("n");
}
