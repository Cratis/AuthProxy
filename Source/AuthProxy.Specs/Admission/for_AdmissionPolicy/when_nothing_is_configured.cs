// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionPolicy;

/// <summary>
/// A deployment that never declared an admission section is not gated, and has to stay indistinguishable
/// from this feature not existing at all.
/// </summary>
public class when_nothing_is_configured : given.an_admission_policy
{
    bool _isConfigured;

    void Because() => _isConfigured = _policy.IsConfigured(new C.AuthProxy());

    [Fact] void should_not_gate_the_deployment() => _isConfigured.ShouldBeFalse();
}
