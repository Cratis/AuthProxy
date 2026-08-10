// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;

namespace Cratis.AuthProxy.Invites.for_InvitationAttestationConfigurationValidator.given;

public class an_attestation_configuration : Specification
{
    protected static C.InvitationAttestationSigningKey PrivateKey(string keyId, int keySize = 2048)
    {
        using var rsa = RSA.Create(keySize);
        return new C.InvitationAttestationSigningKey
        {
            KeyId = keyId,
            PrivateKeyPem = rsa.ExportPkcs8PrivateKeyPem(),
        };
    }

    protected static C.AuthProxy Configuration(params C.InvitationAttestationSigningKey[] signingKeys) => new()
    {
        Invite = new C.Invite
        {
            StageUrl = "https://lobby.example.com/_invite/stage",
            ExchangeUrl = "https://lobby.example.com/_invite/exchange",
            TenantClaim = "tenant_id",
            EmailClaim = "email",
            Attestation = new C.InvitationAttestation
            {
                Issuer = "https://auth.example.com",
                Audience = "ada-lobby",
                ActiveKeyId = signingKeys[0].KeyId,
                SigningKeys = signingKeys,
                Lifetime = TimeSpan.FromSeconds(60),
            }
        }
    };

    protected static ValidateOptionsResult Validate(C.AuthProxy configuration) =>
        new InvitationAttestationConfigurationValidator().Validate(null, configuration);
}
