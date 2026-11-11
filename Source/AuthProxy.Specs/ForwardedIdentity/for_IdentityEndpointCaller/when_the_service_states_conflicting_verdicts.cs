// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.ForwardedIdentity.for_IdentityEndpointCaller;

public class when_the_service_states_conflicting_verdicts : given.a_caller_answered_by_the_service
{
    protected override Task<HttpResponseMessage> Respond(CancellationToken cancellationToken) =>
        Task.FromResult(Json(HttpStatusCode.OK, """{"isAuthorized":true,"IsAuthenticated":false,"details":{"name":"n"}}"""));

    async Task Because() => _outcome = await Call(CancellationToken.None);

    [Fact] void should_be_indeterminate() => _outcome.Status.ShouldEqual(IdentityVerificationStatus.Indeterminate);
    [Fact] void should_explain_the_conflict() => _outcome.Reason.ShouldEqual(IdentityVerificationReason.ConflictingVerdict);
    [Fact] void should_keep_the_details() => _outcome.Details["name"]!.GetValue<string>().ShouldEqual("n");
}
