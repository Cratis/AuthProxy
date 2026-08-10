// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites.for_InvitationAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.Invites.for_InvitationAttestationConfigurationValidator;

public class when_valid_signing_keys_overlap_during_rotation : an_attestation_configuration
{
    ValidateOptionsResult _result;

    void Because() => _result = Validate(Configuration(PrivateKey("current"), PrivateKey("previous")));

    [Fact] void should_accept_the_configuration() => _result.Succeeded.ShouldBeTrue();
}
