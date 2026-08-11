// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.SignIns.for_SignInAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// The baseline every rejection is measured against — without it, a validator that rejected everything would
/// make each negative spec below pass for the wrong reason.
/// </summary>
public class and_it_is_complete : a_sign_in_attestation_configuration
{
    ValidateOptionsResult _result;

    void Because() => _result = Validate(Configuration(signingKeys: PrivateKey("current")));

    [Fact] void should_accept_the_configuration() => _result.Succeeded.ShouldBeTrue();
}
