// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_CapabilityVerifier;

/// <summary>
/// Both opaque values have to come back, not one. The transaction identifies the presentation and the
/// challenge is independent of it, so an answer that reproduces only the first proves only that the
/// transaction was seen.
/// </summary>
public class when_the_verifier_answers_about_another_challenge : given.a_capability_verifier
{
    void Establish() => VerifierAnswering((_, _) => Task.FromResult(Answer(true, _presentation.Transaction, "somebody-elses-challenge")));

    async Task Because() => _verification = await _verifier.Verify(_presentation, CancellationToken.None);

    [Fact] void should_not_admit_the_caller() => _verification.IsAdmitted.ShouldBeFalse();
}
