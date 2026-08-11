// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionConfigurationValidator;

/// <summary>
/// Closing the door without saying who holds the key is refused at startup rather than at every request.
/// The alternative is a deployment that starts cleanly and then answers <c>404</c> to everyone alive, with
/// nothing in the answer — by design — to say why.
/// </summary>
public class when_capability_only_names_no_verifier : given.an_admission_configuration_validator
{
    void Establish() => _config.Admission.Capability = null;

    void Because() => _result = _validator.Validate(null, _config);

    [Fact] void should_refuse_the_configuration() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_setting_that_is_missing() => Failures().ShouldContain($"{C.Admission.SectionKey}:Capability:{nameof(C.AdmissionCapability.VerifierUrl)}");
}
