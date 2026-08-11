// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionConfigurationValidator;

/// <summary>
/// A verifier is somewhere, and a relative reference names nowhere AuthProxy could call.
/// </summary>
public class when_capability_only_names_a_relative_verifier : given.an_admission_configuration_validator
{
    void Establish() => _config.Admission.Capability!.VerifierUrl = "/admit";

    void Because() => _result = _validator.Validate(null, _config);

    [Fact] void should_refuse_the_configuration() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_setting() => Failures().ShouldContain($"{C.Admission.SectionKey}:Capability:{nameof(C.AdmissionCapability.VerifierUrl)}");
}
