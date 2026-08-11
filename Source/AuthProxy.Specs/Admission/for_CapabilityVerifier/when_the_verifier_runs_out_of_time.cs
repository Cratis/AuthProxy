// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Admission.for_CapabilityVerifier;

/// <summary>
/// A verifier that has stopped answering is refused rather than waited on. The call sits on the request
/// path of a caller admitted to nothing, so an unbounded wait would be a way to hold connections open.
/// </summary>
public class when_the_verifier_runs_out_of_time : given.a_capability_verifier
{
    void Establish() => VerifierAnswering(
        async (_, cancellationToken) =>
        {
            await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK);
        },
        TimeSpan.FromMilliseconds(50));

    async Task Because() => _verification = await _verifier.Verify(_presentation, CancellationToken.None);

    [Fact] void should_not_admit_the_caller() => _verification.IsAdmitted.ShouldBeFalse();
}
