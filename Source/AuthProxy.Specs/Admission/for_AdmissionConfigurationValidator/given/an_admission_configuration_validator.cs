// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.for_AdmissionConfigurationValidator.given;

/// <summary>
/// The validator and a configuration a spec shapes before running it.
/// </summary>
public class an_admission_configuration_validator : Specification
{
    protected AdmissionConfigurationValidator _validator;
    protected C.AuthProxy _config;
    protected ValidateOptionsResult _result;

    void Establish()
    {
        _validator = new AdmissionConfigurationValidator();
        _config = new C.AuthProxy
        {
            Admission = new C.Admission
            {
                Mode = C.AdmissionMode.CapabilityOnly,
                Capability = new C.AdmissionCapability { VerifierUrl = "https://verifier.test/admit" },
            },
        };
    }

    /// <summary>
    /// Gets everything the validator refused the configuration for.
    /// </summary>
    /// <returns>The failure messages, joined.</returns>
    protected string Failures() => string.Join(Environment.NewLine, _result.Failures ?? []);
}
