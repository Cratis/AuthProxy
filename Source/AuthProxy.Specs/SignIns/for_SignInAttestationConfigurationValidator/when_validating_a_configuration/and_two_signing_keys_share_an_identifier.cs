// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.SignIns.for_SignInAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// A duplicate identifier on a key that is not the active one passes every other check today, and stays
/// harmless right up until the next rotation names it active — at which point the notification path resolves
/// two keys for one identifier. The active-key rule cannot see this, so the uniqueness rule has to.
/// </summary>
public class and_two_signing_keys_share_an_identifier : a_sign_in_attestation_configuration
{
    ValidateOptionsResult _shared;
    ValidateOptionsResult _distinct;

    void Because()
    {
        _shared = Validate(Configuration(signingKeys: [PrivateKey("current"), PrivateKey("previous"), PrivateKey("previous")]));
        _distinct = Validate(Configuration(signingKeys: [PrivateKey("current"), PrivateKey("previous"), PrivateKey("retired")]));
    }

    [Fact] void should_reject_a_duplicate_on_a_key_that_is_not_active() => _shared.Succeeded.ShouldBeFalse();
    [Fact] void should_accept_the_same_rotation_with_distinct_identifiers() => _distinct.Succeeded.ShouldBeTrue();
}
