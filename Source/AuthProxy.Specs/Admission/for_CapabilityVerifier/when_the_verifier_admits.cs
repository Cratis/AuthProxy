// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_CapabilityVerifier;

/// <summary>
/// A verifier that says yes about this exact presentation admits the caller, and that is the whole of what
/// comes back — a yes carries nothing else, because anything else would be sealed into a browser cookie
/// whose size the deployment, not this proxy, would then control.
/// </summary>
public class when_the_verifier_admits : given.a_capability_verifier
{
    void Establish() => VerifierAnswering((_, _) => Task.FromResult(Answer(
        true,
        _presentation.Transaction,
        _presentation.Challenge)));

    async Task Because() => _verification = await _verifier.Verify(_presentation, CancellationToken.None);

    [Fact] void should_admit_the_caller() => _verification.IsAdmitted.ShouldBeTrue();
    [Fact] void should_not_write_the_capability_anywhere_a_log_sink_can_read_it() => _logger.Text.Contains(Capability, StringComparison.Ordinal).ShouldBeFalse();
}
