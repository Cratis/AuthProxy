// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// A section with no keys at all is a deployment that asked to sign and cannot.
/// </summary>
public class and_no_signing_key_is_configured : a_forwarding_attestation_configuration
{
    ValidateOptionsResult _result;

    void Because() => _result = Validate(new C.AuthProxy { ForwardingAttestation = new C.ForwardingAttestation { Issuer = "https://auth.example.com", ActiveKeyId = "current" } });

    [Fact] void should_reject_the_configuration() => _result.Succeeded.ShouldBeFalse();
}
