// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// The key identifier is what the verifier selects a public key by, so two keys under one identifier would make
/// verification depend on which one happened to be active.
/// </summary>
public class and_two_signing_keys_share_an_identifier : a_forwarding_attestation_configuration
{
    ValidateOptionsResult _result;

    void Because() => _result = Validate(Configuration(signingKeys: [P256Key("current"), P256Key("current")]));

    [Fact] void should_reject_the_configuration() => _result.Succeeded.ShouldBeFalse();
}
