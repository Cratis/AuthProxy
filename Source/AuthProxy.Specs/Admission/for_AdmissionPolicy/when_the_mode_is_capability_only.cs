// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionPolicy;

/// <summary>
/// The mode is the whole switch. Nothing else in the configuration turns admission on, and nothing else
/// turns it off.
/// </summary>
public class when_the_mode_is_capability_only : given.an_admission_policy
{
    bool _isConfigured;

    void Because() => _isConfigured = _policy.IsConfigured(_config);

    [Fact] void should_gate_the_deployment() => _isConfigured.ShouldBeTrue();
}
