// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// An active key that is not configured would leave the signer with nothing to sign with, failing every request.
/// </summary>
public class and_the_active_key_identifier_matches_no_key : a_forwarding_attestation_configuration
{
    ValidateOptionsResult _result;

    void Because() => _result = Validate(Configuration(activeKeyId: "next", signingKeys: P256Key("current")));

    [Fact] void should_reject_the_configuration() => _result.Succeeded.ShouldBeFalse();
}
