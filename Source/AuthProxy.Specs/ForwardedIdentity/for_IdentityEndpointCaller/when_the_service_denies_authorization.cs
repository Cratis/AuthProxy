// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.ForwardedIdentity.for_IdentityEndpointCaller;

public class when_the_service_denies_authorization : given.a_caller_answered_by_the_service
{
    protected override Task<HttpResponseMessage> Respond(CancellationToken cancellationToken) =>
        Task.FromResult(Json(HttpStatusCode.OK, """{"isAuthorized":false,"isAuthenticated":true}"""));

    async Task Because() => _outcome = await Call(CancellationToken.None);

    [Fact] void should_be_denied() => _outcome.Status.ShouldEqual(IdentityVerificationStatus.Denied);
    [Fact] void should_explain_the_denial() => _outcome.Reason.ShouldEqual(IdentityVerificationReason.NotAuthorized);
}
