// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Admission.for_CapabilityVerifier;

/// <summary>
/// A verifier having a bad day is not a verifier saying yes.
/// </summary>
public class when_the_verifier_answers_with_an_error_status : given.a_capability_verifier
{
    void Establish() => VerifierAnswering((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError)));

    async Task Because() => _verification = await _verifier.Verify(_presentation, CancellationToken.None);

    [Fact] void should_not_admit_the_caller() => _verification.IsAdmitted.ShouldBeFalse();
}
