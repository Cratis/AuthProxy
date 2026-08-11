// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;

namespace Cratis.AuthProxy.SignIns.for_SignInAttestationConfigurationValidator.given;

public class a_sign_in_attestation_configuration : Specification
{
    protected const string NotifyUrl = "https://studio.example.com/api/internal/sign-ins";

    protected static C.SignInAttestationSigningKey PrivateKey(string keyId, int keySize = 2048)
    {
        using var rsa = RSA.Create(keySize);
        return new C.SignInAttestationSigningKey
        {
            KeyId = keyId,
            PrivateKeyPem = rsa.ExportPkcs8PrivateKeyPem(),
        };
    }

    protected static C.AuthProxy Configuration(
        string notifyUrl = NotifyUrl,
        string? activeKeyId = null,
        TimeSpan? lifetime = null,
        params C.SignInAttestationSigningKey[] signingKeys) => new()
        {
            SignIn = new C.SignIn
            {
                NotifyUrl = notifyUrl,
                Attestation = new C.SignInAttestation
                {
                    Issuer = "https://auth.example.com",
                    Audience = "ada",
                    ActiveKeyId = activeKeyId ?? signingKeys[0].KeyId,
                    SigningKeys = signingKeys,
                    Lifetime = lifetime ?? TimeSpan.FromSeconds(60),
                }
            }
        };

    protected static ValidateOptionsResult Validate(C.AuthProxy configuration) =>
        new SignInAttestationConfigurationValidator().Validate(null, configuration);
}
