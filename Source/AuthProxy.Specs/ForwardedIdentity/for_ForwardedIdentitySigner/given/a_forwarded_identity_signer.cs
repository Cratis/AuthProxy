// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Cratis.AuthProxy.Admission.given;
using Microsoft.Extensions.Logging.Abstractions;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigner.given;

public class a_forwarded_identity_signer : Specification
{
    protected const string Issuer = "https://auth.example.com";
    protected const string KeyId = "current";
    protected const string Subject = "9f8a7c1e-4b2d-4f6a-8e3b-1c2d3e4f5a6b";
    protected const string Tenant = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
    protected static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1767225600);

    protected ECDsa _key;
    protected string _publicKeyPem;
    protected C.AuthProxy _configuration;
    protected ForwardedIdentitySigner _signer;

    void Establish()
    {
        _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _publicKeyPem = _key.ExportSubjectPublicKeyInfoPem();
        _configuration = new C.AuthProxy
        {
            ForwardingAttestation = Attestation(_key.ExportPkcs8PrivateKeyPem()),
            Services = new Dictionary<string, C.Service>
            {
                ["reports"] = new C.Service { Backend = new C.ServiceEndpoint { BaseUrl = "https://reports.internal" } },
            },
        };

        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(_ => _configuration);
        _signer = new ForwardedIdentitySigner(config, new FixedTime(Now), NullLogger<ForwardedIdentitySigner>.Instance);
    }

    void Destroy()
    {
        _signer.Dispose();
        _key.Dispose();
    }

    protected virtual C.ForwardingAttestation? Attestation(string privateKeyPem) => new()
    {
        Issuer = Issuer,
        ActiveKeyId = KeyId,
        SigningKeys = [new C.ForwardingAttestationSigningKey { KeyId = KeyId, PrivateKeyPem = privateKeyPem }],
    };

    protected static HttpRequestMessage Request(string url = "https://reports.internal/api/reports/42?expand=true", params (string Name, string Value)[] headers)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, url);
        foreach (var (name, value) in headers)
        {
            request.Headers.TryAddWithoutValidation(name, value);
        }

        return request;
    }

    protected static string AssertionOf(HttpRequestMessage request) =>
        request.Headers.TryGetValues(Headers.ForwardedIdentity, out var values) ? values.Single() : string.Empty;
}
