// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// The baseline every rejection is measured against: without it, a validator that rejected everything would make
/// each negative spec pass for the wrong reason.
/// </summary>
public class and_it_is_complete : a_forwarding_attestation_configuration
{
    ValidateOptionsResult _result;
    ValidateOptionsResult _rotating;

    void Because()
    {
        _result = Validate(Configuration(signingKeys: P256Key("current")));
        _rotating = Validate(Configuration(activeKeyId: "next", signingKeys: [P256Key("current"), P256Key("next")]));
    }

    [Fact] void should_accept_the_configuration() => _result.Succeeded.ShouldBeTrue();
    [Fact] void should_accept_a_second_key_during_rotation() => _rotating.Succeeded.ShouldBeTrue();
}
