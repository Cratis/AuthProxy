// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionConfigurationValidator;

/// <summary>
/// A bound of nothing, a lifetime of nothing and a path that is not a path all refuse every caller, so each
/// is named at startup instead.
/// </summary>
public class when_capability_only_declares_an_unusable_bound : given.an_admission_configuration_validator
{
    void Establish()
    {
        _config.Admission.Capability!.MaximumLength = 0;
        _config.Admission.Capability.Path = "admission";
        _config.Admission.EntryLifetime = TimeSpan.Zero;
    }

    void Because() => _result = _validator.Validate(null, _config);

    [Fact] void should_refuse_the_configuration() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_bound() => Failures().ShouldContain(nameof(C.AdmissionCapability.MaximumLength));
    [Fact] void should_name_the_path() => Failures().ShouldContain(nameof(C.AdmissionCapability.Path));
    [Fact] void should_name_the_lifetime() => Failures().ShouldContain(nameof(C.Admission.EntryLifetime));
}
