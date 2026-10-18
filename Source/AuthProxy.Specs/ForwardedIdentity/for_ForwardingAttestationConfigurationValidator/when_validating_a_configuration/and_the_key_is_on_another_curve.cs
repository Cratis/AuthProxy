// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// ES256 means P-256. A P-384 key is a valid EC key, which is exactly why it has to be rejected by curve and not by type.
/// </summary>
public class and_the_key_is_on_another_curve : a_forwarding_attestation_configuration
{
    ValidateOptionsResult _result;

    void Because()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        _result = Validate(Configuration(signingKeys: new C.ForwardingAttestationSigningKey { KeyId = "current", PrivateKeyPem = key.ExportPkcs8PrivateKeyPem() }));
    }

    [Fact] void should_reject_the_configuration() => _result.Succeeded.ShouldBeFalse();
}
