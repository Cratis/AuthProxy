// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionPolicy;

/// <summary>
/// Naming the default explicitly is still the default. A deployment that writes
/// <c>Mode: Public</c> — or that carries a capability section it has not switched on — is gated by nothing.
/// </summary>
public class when_the_mode_is_public : given.an_admission_policy
{
    bool _isConfigured;

    void Establish() => _config.Admission.Mode = C.AdmissionMode.Public;

    void Because() => _isConfigured = _policy.IsConfigured(_config);

    [Fact] void should_not_gate_the_deployment() => _isConfigured.ShouldBeFalse();
}
