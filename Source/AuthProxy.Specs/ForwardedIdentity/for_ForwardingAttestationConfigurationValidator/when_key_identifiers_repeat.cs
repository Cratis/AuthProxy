// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator;

/// <summary>
/// A verifier selects the public key by <c language="text">kid</c>, so two keys under one identifier make the
/// signing key ambiguous.
/// </summary>
public class when_key_identifiers_repeat : given.a_signing_deployment
{
    void Establish()
    {
        var attestation = _configuration.ForwardingAttestation!;
        attestation.SigningKeys.Add(new C.ForwardingAttestationSigningKey { KeyId = KeyId, PrivateKeyPem = attestation.SigningKeys[0].PrivateKeyPem });
    }

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_require_unique_identifiers() => HasFailure("ForwardingAttestation.SigningKeys must use unique, case-sensitive key identifiers.").ShouldBeTrue();
}
