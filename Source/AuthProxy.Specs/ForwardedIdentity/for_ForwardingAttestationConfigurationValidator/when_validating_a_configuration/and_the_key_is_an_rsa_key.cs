// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// The contract is ES256 only; an RSA key would make every forwarded request fail with a 502, so it fails startup.
/// </summary>
public class and_the_key_is_an_rsa_key : a_forwarding_attestation_configuration
{
    ValidateOptionsResult _result;

    void Because()
    {
        using var rsa = RSA.Create(2048);
        _result = Validate(Configuration(signingKeys: new C.ForwardingAttestationSigningKey { KeyId = "current", PrivateKeyPem = rsa.ExportPkcs8PrivateKeyPem() }));
    }

    [Fact] void should_reject_the_configuration() => _result.Succeeded.ShouldBeFalse();
}
