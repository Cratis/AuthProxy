// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites.for_InvitationAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.Invites.for_InvitationAttestationConfigurationValidator;

public class when_a_malformed_signing_key_is_configured : an_attestation_configuration
{
    ValidateOptionsResult _result;

    void Because() => _result = Validate(Configuration(new C.InvitationAttestationSigningKey
    {
        KeyId = "current",
        PrivateKeyPem = "not-a-private-key",
    }));

    [Fact] void should_reject_the_configuration() => _result.Succeeded.ShouldBeFalse();
}
