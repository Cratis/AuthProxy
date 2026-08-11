// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionPolicy;

/// <summary>
/// The runtime half of the same guard the validator states at startup. The startup refusal is the one an
/// operator sees, but it only runs while something registers the validator — so the gate itself has to reach
/// the closed answer on its own, from a mode it cannot recognize, rather than treating "not capability-only"
/// as permission to answer everybody.
/// </summary>
public class when_the_mode_is_not_recognized : given.an_admission_policy
{
    bool _isConfigured;

    void Establish() => _config.Admission.Mode = (C.AdmissionMode)2;

    void Because() => _isConfigured = _policy.IsConfigured(_config);

    [Fact] void should_gate_the_deployment() => _isConfigured.ShouldBeTrue();
}
