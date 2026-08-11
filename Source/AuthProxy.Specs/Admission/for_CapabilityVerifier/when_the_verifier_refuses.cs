// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_CapabilityVerifier;

/// <summary>
/// A verifier that says no is the ordinary refusal — an expired, revoked, already-used or simply unknown
/// capability all arrive here as the same answer, because AuthProxy never asked which it was.
/// </summary>
public class when_the_verifier_refuses : given.a_capability_verifier
{
    void Establish() => VerifierAnswering((_, _) => Task.FromResult(Answer(false, _presentation.Transaction, _presentation.Challenge)));

    async Task Because() => _verification = await _verifier.Verify(_presentation, CancellationToken.None);

    [Fact] void should_not_admit_the_caller() => _verification.IsAdmitted.ShouldBeFalse();
    [Fact] void should_carry_no_context() => _verification.Context.ShouldBeEmpty();
    [Fact] void should_not_write_the_capability_anywhere_a_log_sink_can_read_it() => _logger.Text.Contains(Capability, StringComparison.Ordinal).ShouldBeFalse();
}
