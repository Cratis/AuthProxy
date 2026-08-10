// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites.for_InvitationAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.Invites.for_InvitationAttestationConfigurationValidator;

public class when_attestation_lifetime_exceeds_sixty_seconds : an_attestation_configuration
{
    ValidateOptionsResult _result;

    void Because()
    {
        var configuration = Configuration(PrivateKey("current"));
        configuration.Invite!.Attestation!.Lifetime = TimeSpan.FromSeconds(61);
        _result = Validate(configuration);
    }

    [Fact] void should_reject_the_configuration() => _result.Succeeded.ShouldBeFalse();
}
