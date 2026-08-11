// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionConfigurationValidator;

/// <summary>
/// A deployment that has not opted in is not held to any of this, whatever else its configuration says.
/// </summary>
public class when_the_mode_is_public : given.an_admission_configuration_validator
{
    void Establish()
    {
        _config.Admission = new C.Admission();
        _config.Invite = new C.Invite();
    }

    void Because() => _result = _validator.Validate(null, _config);

    [Fact] void should_accept_the_configuration() => _result.Succeeded.ShouldBeTrue();
}
