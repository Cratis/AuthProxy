// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator;

/// <summary>
/// The other signed messages use RSA keys, so pasting one of those here is a likely mistake; it is refused at startup
/// rather than turning every request into a 502.
/// </summary>
public class when_the_signing_key_is_an_rsa_key : given.a_signing_deployment
{
    void Establish()
    {
        using var key = RSA.Create(2048);
        _configuration.ForwardingAttestation!.SigningKeys[0].PrivateKeyPem = key.ExportPkcs8PrivateKeyPem();
    }

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_require_a_valid_p256_key() => HasFailure("ForwardingAttestation.SigningKeys.PrivateKeyPem must contain a valid EC P-256 private key.").ShouldBeTrue();
}
