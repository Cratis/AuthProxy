// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionConfigurationValidator;

/// <summary>
/// A closed deployment that names its verifier starts.
/// </summary>
public class when_capability_only_is_fully_declared : given.an_admission_configuration_validator
{
    void Because() => _result = _validator.Validate(null, _config);

    [Fact] void should_accept_the_configuration() => _result.Succeeded.ShouldBeTrue();
}
