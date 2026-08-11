// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_CapabilityVerifier;

/// <summary>
/// A verifier that says yes about this exact presentation admits the caller, and whatever opaque context it
/// asked to have carried is carried.
/// </summary>
public class when_the_verifier_admits : given.a_capability_verifier
{
    void Establish() => VerifierAnswering((_, _) => Task.FromResult(Answer(
        true,
        _presentation.Transaction,
        _presentation.Challenge,
        new Dictionary<string, string>(StringComparer.Ordinal) { ["scope"] = "opaque" })));

    async Task Because() => _verification = await _verifier.Verify(_presentation, CancellationToken.None);

    [Fact] void should_admit_the_caller() => _verification.IsAdmitted.ShouldBeTrue();
    [Fact] void should_carry_the_context_the_verifier_asked_for() => _verification.Context["scope"].ShouldEqual("opaque");
    [Fact] void should_not_write_the_capability_anywhere_a_log_sink_can_read_it() => _logger.Text.Contains(Capability, StringComparison.Ordinal).ShouldBeFalse();
}
