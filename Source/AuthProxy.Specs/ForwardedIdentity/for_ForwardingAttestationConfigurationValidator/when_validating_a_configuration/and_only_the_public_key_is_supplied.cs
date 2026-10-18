// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// A public key pasted where the private key belongs imports cleanly and can never sign, so it fails startup.
/// </summary>
public class and_only_the_public_key_is_supplied : a_forwarding_attestation_configuration
{
    ValidateOptionsResult _result;

    void Because()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _result = Validate(Configuration(signingKeys: new C.ForwardingAttestationSigningKey { KeyId = "current", PrivateKeyPem = key.ExportSubjectPublicKeyInfoPem() }));
    }

    [Fact] void should_reject_the_configuration() => _result.Succeeded.ShouldBeFalse();
}
