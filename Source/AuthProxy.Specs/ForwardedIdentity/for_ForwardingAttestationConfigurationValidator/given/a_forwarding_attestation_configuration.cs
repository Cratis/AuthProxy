// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.given;

public class a_forwarding_attestation_configuration : Specification
{
    protected static C.ForwardingAttestationSigningKey P256Key(string keyId)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new C.ForwardingAttestationSigningKey { KeyId = keyId, PrivateKeyPem = key.ExportPkcs8PrivateKeyPem() };
    }

    protected static C.AuthProxy Configuration(
        string? activeKeyId = null,
        TimeSpan? lifetime = null,
        string issuer = "https://auth.example.com",
        params C.ForwardingAttestationSigningKey[] signingKeys) => new()
        {
            ForwardingAttestation = new C.ForwardingAttestation
            {
                Issuer = issuer,
                ActiveKeyId = activeKeyId ?? signingKeys[0].KeyId,
                SigningKeys = signingKeys,
                Lifetime = lifetime ?? TimeSpan.FromSeconds(30),
            },
        };

    protected static C.AuthProxy WithTenantSelection(C.AuthProxy configuration, string tenantsEndpoint, string? forwardingAudience = null, params (string Name, string BaseUrl, string? Audience)[] services)
    {
        configuration.TenantResolutions =
        [
            new C.TenantResolution
            {
                Strategy = C.TenantSourceIdentifierResolverType.Selection,
                Options = new SelectionOptions { TenantsEndpoint = tenantsEndpoint, ForwardingAudience = forwardingAudience },
            },
        ];

        foreach (var (name, baseUrl, audience) in services)
        {
            configuration.Services[name] = new C.Service
            {
                Backend = new C.ServiceEndpoint { BaseUrl = baseUrl },
                ForwardingAudience = audience,
            };
        }

        return configuration;
    }

    protected static ValidateOptionsResult Validate(C.AuthProxy configuration) =>
        new ForwardingAttestationConfigurationValidator().Validate(null, configuration);
}
