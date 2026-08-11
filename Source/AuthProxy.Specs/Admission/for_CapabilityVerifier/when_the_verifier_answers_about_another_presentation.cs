// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_CapabilityVerifier;

/// <summary>
/// A yes that names a different transaction is not a yes about this caller. Accepting it would make any
/// admitting answer the verifier has ever produced usable against any presentation.
/// </summary>
public class when_the_verifier_answers_about_another_presentation : given.a_capability_verifier
{
    void Establish() => VerifierAnswering((_, _) => Task.FromResult(Answer(true, "somebody-elses-transaction", _presentation.Challenge)));

    async Task Because() => _verification = await _verifier.Verify(_presentation, CancellationToken.None);

    [Fact] void should_not_admit_the_caller() => _verification.IsAdmitted.ShouldBeFalse();
}
