// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator;

/// <summary>
/// ES256 is defined on P-256 only. A key on another curve would sign assertions no verifier accepts.
/// </summary>
public class when_the_signing_key_is_on_another_curve : given.a_signing_deployment
{
    void Establish()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        _configuration.ForwardingAttestation!.SigningKeys[0].PrivateKeyPem = key.ExportPkcs8PrivateKeyPem();
    }

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_require_a_p256_key() => HasFailure("ForwardingAttestation.SigningKeys.PrivateKeyPem must contain an EC P-256 private key.").ShouldBeTrue();
}
