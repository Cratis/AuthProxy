// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_CapabilityVerifier;

public class when_local_development_uses_an_http_verifier_with_signing : given.a_capability_verifier
{
    void Establish()
    {
        VerifierAnswering((_, _) => Task.FromResult(Answer(true, _presentation.Transaction, _presentation.Challenge)));
        _config.Profile = C.DeploymentProfile.LocalDevelopment;
        _config.Services["signed"] = new() { Backend = new() { BaseUrl = "https://app.example" }, ForwardedIdentity = new() };
        _config.Admission.Capability!.VerifierUrl = "http://verifier.example/verify";
    }

    async Task Because() => _verification = await _verifier.Verify(_presentation, CancellationToken.None);

    [Fact] void should_admit_the_presentation() => _verification.IsAdmitted.ShouldBeTrue();
    [Fact] void should_call_the_verifier() => _httpClientFactory.Calls.ShouldEqual(1);
}
