// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites.for_InvitationAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.Invites.for_InvitationAttestationConfigurationValidator.when_signing_key_identifiers_are_duplicated;

public class and_the_duplicate_is_the_active_key : an_attestation_configuration
{
    ValidateOptionsResult _result;

    void Because() => _result = Validate(Configuration(PrivateKey("current"), PrivateKey("current")));

    [Fact] void should_reject_the_configuration() => _result.Succeeded.ShouldBeFalse();
}
