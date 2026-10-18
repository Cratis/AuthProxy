// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// The key identifier travels in the JOSE header and is matched byte for byte by the verifier, so it is kept to a
/// plain ASCII identifier.
/// </summary>
public class and_a_key_identifier_is_not_an_ascii_identifier : a_forwarding_attestation_configuration
{
    ValidateOptionsResult _result;

    void Because() => _result = Validate(Configuration(signingKeys: P256Key("nøkkel 1")));

    [Fact] void should_reject_the_configuration() => _result.Succeeded.ShouldBeFalse();
}
