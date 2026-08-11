// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.SignIns.for_SignInAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// Configuration binding produces a null identifier for a key section that omits it, and startup validation is
/// the one place that must survive every shape a deployer can hand it. Reporting the failure is the whole
/// point of the validator; throwing out of it turns a fixable misconfiguration into a process that will not
/// start with no statement of what is wrong.
/// </summary>
public class and_a_signing_key_has_no_identifier : a_sign_in_attestation_configuration
{
    ValidateOptionsResult _result;
    Exception _error;

    void Because()
    {
        var key = PrivateKey("current");
        key.KeyId = null!;
        _error = Catch.Exception(() => _result = Validate(Configuration(activeKeyId: "current", signingKeys: [key])));
    }

    [Fact] void should_report_the_failure_rather_than_throw() => _error.ShouldBeNull();
    [Fact] void should_reject_the_configuration() => _result.Succeeded.ShouldBeFalse();
}
