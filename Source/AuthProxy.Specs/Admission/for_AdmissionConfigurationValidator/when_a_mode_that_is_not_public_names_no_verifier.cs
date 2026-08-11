// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionConfigurationValidator;

/// <summary>
/// Every mode that is not <see cref="C.AdmissionMode.Public"/> is held to the capability configuration —
/// stated over the enum rather than over the one mode that exists today.
/// </summary>
/// <remarks>
/// <see cref="Admission.IAdmissionPolicy.IsConfigured"/> turns the gate on for every mode that is not
/// public, so any mode the validator skips is a deployment that starts clean and then refuses every caller
/// alive with a <c>404</c> that says nothing. Two of the three places that branch on the mode were corrected
/// to ask "is this public"; this is what stops the third from drifting back, and what makes adding a third
/// mode fail here rather than in production.
/// </remarks>
public class when_a_mode_that_is_not_public_names_no_verifier : given.an_admission_configuration_validator
{
    readonly List<string> _accepted = [];

    void Because()
    {
        foreach (var mode in Enum.GetValues<C.AdmissionMode>().Where(mode => mode != C.AdmissionMode.Public))
        {
            _config.Admission = new C.Admission { Mode = mode };

            if (_validator.Validate(null, _config).Succeeded)
            {
                _accepted.Add(mode.ToString());
            }
        }
    }

    [Fact] void should_refuse_every_one_of_them() => _accepted.ShouldBeEmpty();
}
