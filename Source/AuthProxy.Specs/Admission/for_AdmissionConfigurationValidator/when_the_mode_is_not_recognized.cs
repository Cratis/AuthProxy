// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionConfigurationValidator;

/// <summary>
/// The mode is asked about before anything else, because everything below is asked of a mode that was
/// understood. A value outside the enum is neither <c>Public</c> nor <c>CapabilityOnly</c>, so the early
/// return for "not capability-only" would hand it straight past every check here — leaving a deployment that
/// asked to be closed accepted as configured, and gated by nothing.
/// </summary>
public class when_the_mode_is_not_recognized : given.an_admission_configuration_validator
{
    void Establish() => _config.Admission.Mode = (C.AdmissionMode)2;

    void Because() => _result = _validator.Validate(null, _config);

    [Fact] void should_refuse_the_configuration() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_setting_that_carries_it() => Failures().ShouldContain($"{C.Admission.SectionKey}:{nameof(C.Admission.Mode)}");
    [Fact] void should_say_what_it_could_have_been() => Failures().ShouldContain(nameof(C.AdmissionMode.CapabilityOnly));
}
