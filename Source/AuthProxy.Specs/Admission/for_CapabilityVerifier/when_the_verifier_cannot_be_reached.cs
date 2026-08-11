// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_CapabilityVerifier;

/// <summary>
/// An outage of the verifier is an outage of admission, never a suspension of it. Failing open here would
/// mean the whole mode is one unreachable service away from being nothing at all.
/// </summary>
public class when_the_verifier_cannot_be_reached : given.a_capability_verifier
{
    void Establish() => VerifierAnswering((_, _) => throw new HttpRequestException("connection refused"));

    async Task Because() => _verification = await _verifier.Verify(_presentation, CancellationToken.None);

    [Fact] void should_not_admit_the_caller() => _verification.IsAdmitted.ShouldBeFalse();
    [Fact] void should_not_write_the_capability_anywhere_a_log_sink_can_read_it() => _logger.Text.Contains(Capability, StringComparison.Ordinal).ShouldBeFalse();
}
