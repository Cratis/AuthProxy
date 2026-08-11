// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.SignIns.for_SignInAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// Opting in to signing and then configuring no key at all is the one misconfiguration that looks completely
/// harmless: nothing is malformed, nothing is out of bounds, and at run time every sign-in simply stops being
/// recorded. It has to fail at startup, like every other unusable signing configuration.
/// </summary>
public class and_no_signing_key_is_configured : a_sign_in_attestation_configuration
{
    ValidateOptionsResult _empty;
    ValidateOptionsResult _oneKey;

    void Because()
    {
        _empty = Validate(Configuration(activeKeyId: "current", signingKeys: []));
        _oneKey = Validate(Configuration(activeKeyId: "current", signingKeys: PrivateKey("current")));
    }

    [Fact] void should_reject_a_signing_configuration_with_no_keys() => _empty.Succeeded.ShouldBeFalse();
    [Fact] void should_accept_the_same_configuration_once_the_key_is_supplied() => _oneKey.Succeeded.ShouldBeTrue();
}
