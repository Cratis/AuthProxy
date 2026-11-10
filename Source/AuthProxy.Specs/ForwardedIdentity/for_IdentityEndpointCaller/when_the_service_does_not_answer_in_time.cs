// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.ForwardedIdentity.for_IdentityEndpointCaller;

public class when_the_service_does_not_answer_in_time : given.a_caller_answered_by_the_service
{
    void Establish() => _timeout = TimeSpan.FromMilliseconds(50);

    protected override async Task<HttpResponseMessage> Respond(CancellationToken cancellationToken)
    {
        await Task.Delay(Timeout.Infinite, cancellationToken);
        return Json(HttpStatusCode.OK, "{}");
    }

    [Fact] void should_be_indeterminate() => _outcome.Status.ShouldEqual(IdentityVerificationStatus.Indeterminate);
    [Fact] void should_explain_the_timeout() => _outcome.Reason.ShouldEqual(IdentityVerificationReason.TimedOut);
}
