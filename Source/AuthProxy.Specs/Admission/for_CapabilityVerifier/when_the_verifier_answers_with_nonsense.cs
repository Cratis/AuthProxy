// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text;

namespace Cratis.AuthProxy.Admission.for_CapabilityVerifier;

/// <summary>
/// A body that is not an answer is not an answer, however successful the status that carried it.
/// </summary>
public class when_the_verifier_answers_with_nonsense : given.a_capability_verifier
{
    void Establish() => VerifierAnswering((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
    {
        Content = new StringContent("this is not json", Encoding.UTF8, "application/json"),
    }));

    async Task Because() => _verification = await _verifier.Verify(_presentation, CancellationToken.None);

    [Fact] void should_not_admit_the_caller() => _verification.IsAdmitted.ShouldBeFalse();
}
