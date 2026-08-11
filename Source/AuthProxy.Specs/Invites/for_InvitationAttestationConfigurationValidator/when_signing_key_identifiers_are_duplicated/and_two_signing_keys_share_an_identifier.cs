// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites.for_InvitationAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.Invites.for_InvitationAttestationConfigurationValidator.when_signing_key_identifiers_are_duplicated;

/// <summary>
/// A duplicate on the active key is caught by the active-key rule, so it proves nothing about the uniqueness
/// rule. A duplicate on any other key is the case only the uniqueness rule can see — and the one that lies in
/// wait until a rotation makes that identifier active.
/// </summary>
public class and_two_signing_keys_share_an_identifier : an_attestation_configuration
{
    ValidateOptionsResult _shared;
    ValidateOptionsResult _distinct;

    void Because()
    {
        _shared = Validate(Configuration(PrivateKey("current"), PrivateKey("previous"), PrivateKey("previous")));
        _distinct = Validate(Configuration(PrivateKey("current"), PrivateKey("previous"), PrivateKey("retired")));
    }

    [Fact] void should_reject_a_duplicate_on_a_key_that_is_not_active() => _shared.Succeeded.ShouldBeFalse();
    [Fact] void should_accept_the_same_rotation_with_distinct_identifiers() => _distinct.Succeeded.ShouldBeTrue();
}
