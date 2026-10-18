// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.given;

/// <summary>
/// A deployment that signs what it forwards with one usable EC P-256 key, routing to one service, and the
/// validator that judges it at startup.
/// </summary>
public class a_signing_deployment : Specification
{
    protected const string KeyId = "current";

    private protected ForwardingAttestationConfigurationValidator _validator;
    protected C.AuthProxy _configuration;
    protected ValidateOptionsResult _result;

    void Establish()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _validator = new();
        _configuration = new C.AuthProxy
        {
            ForwardingAttestation = new C.ForwardingAttestation
            {
                Issuer = "https://auth.example.com",
                ActiveKeyId = KeyId,
                SigningKeys = [new C.ForwardingAttestationSigningKey { KeyId = KeyId, PrivateKeyPem = key.ExportPkcs8PrivateKeyPem() }],
            },
            Services = new Dictionary<string, C.Service>
            {
                ["reports"] = new C.Service { Backend = new C.ServiceEndpoint { BaseUrl = "http://reports-api:8080/" } },
            },
        };
    }

    protected void Validate() => _result = _validator.Validate(null, _configuration);

    protected void SelectTenantsFrom(string endpoint, string? audience = null) =>
        _configuration.TenantResolutions =
        [
            new C.TenantResolution
            {
                Strategy = C.TenantSourceIdentifierResolverType.Selection,
                Options = new SelectionOptions { TenantsEndpoint = endpoint, ForwardingAudience = audience },
            },
        ];

    protected bool HasFailure(string text) => _result.Failures?.Any(_ => _.Contains(text, StringComparison.Ordinal)) ?? false;
}
