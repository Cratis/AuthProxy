// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_CapabilityVerifier;

/// <summary>
/// Startup validation refuses a closed deployment naming no verifier, so this is the second line rather
/// than the first — and it closes rather than opens.
/// </summary>
public class when_no_verifier_is_configured : given.a_capability_verifier
{
    void Establish()
    {
        _config.Admission.Capability = null;
        VerifierAnswering((_, _) => Task.FromResult(Answer(true, _presentation.Transaction, _presentation.Challenge)));
    }

    async Task Because() => _verification = await _verifier.Verify(_presentation, CancellationToken.None);

    [Fact] void should_not_admit_the_caller() => _verification.IsAdmitted.ShouldBeFalse();
    [Fact] void should_not_call_anything() => _httpClientFactory.Calls.ShouldEqual(0);
}
