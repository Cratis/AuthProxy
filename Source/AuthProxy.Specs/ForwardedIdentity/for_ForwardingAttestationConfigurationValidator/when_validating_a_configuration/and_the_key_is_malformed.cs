// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// A PEM block that is not a key at all fails startup instead of failing every request.
/// </summary>
public class and_the_key_is_malformed : a_forwarding_attestation_configuration
{
    ValidateOptionsResult _malformed;
    ValidateOptionsResult _empty;

    void Because()
    {
        _malformed = Validate(Configuration(signingKeys: new C.ForwardingAttestationSigningKey { KeyId = "current", PrivateKeyPem = "-----BEGIN PRIVATE KEY-----\nbm90LWEta2V5\n-----END PRIVATE KEY-----" }));
        _empty = Validate(Configuration(signingKeys: new C.ForwardingAttestationSigningKey { KeyId = "current", PrivateKeyPem = string.Empty }));
    }

    [Fact] void should_reject_a_malformed_key() => _malformed.Succeeded.ShouldBeFalse();
    [Fact] void should_reject_a_missing_key() => _empty.Succeeded.ShouldBeFalse();
}
