// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.SignIns.for_SignInAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// An RS256 key below 2048 bits would still sign, so nothing at run time would ever complain — the strength
/// of the whole binding has to be checked where it is configured.
/// </summary>
public class and_an_undersized_signing_key_is_configured : a_sign_in_attestation_configuration
{
    ValidateOptionsResult _result;

    void Because() => _result = Validate(Configuration(signingKeys: PrivateKey("current", 1024)));

    [Fact] void should_reject_the_configuration() => _result.Succeeded.ShouldBeFalse();
}
