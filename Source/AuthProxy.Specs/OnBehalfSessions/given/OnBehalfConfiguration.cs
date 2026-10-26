// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.OnBehalfSessions.given;

/// <summary>
/// Builds a valid on-behalf configuration and keeps the public half of its signing key for verification.
/// </summary>
public sealed class OnBehalfConfiguration
{
    public const string Issuer = "https://auth.example.com";
    public const string Audience = "usher";
    public const string KeyId = "on-behalf-2026-09";
    public const string ServiceName = "portal";
    public const string BackendUrl = "https://portal.internal";
    public const string SupportClaim = "roles";
    public const string SupportRole = "support";

    public OnBehalfConfiguration()
    {
        using var rsa = RSA.Create(2048);
        ValidationKey = new RsaSecurityKey(rsa.ExportParameters(false)) { KeyId = KeyId };
        Value = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                [ServiceName] = new() { Backend = new() { BaseUrl = BackendUrl } },
            },
            OnBehalf = new C.OnBehalf
            {
                Service = ServiceName,
                ActorAuthorization = new()
                {
                    RequiredClaims = [new C.ClaimRequirement { Claim = SupportClaim, AnyOf = [SupportRole] }],
                },
                Attestation = new C.OnBehalfAttestation
                {
                    Issuer = Issuer,
                    Audience = Audience,
                    ActiveKeyId = KeyId,
                    SigningKeys = [new C.OnBehalfAttestationSigningKey { KeyId = KeyId, PrivateKeyPem = rsa.ExportPkcs8PrivateKeyPem() }],
                },
            },
        };

        Monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        Monitor.CurrentValue.Returns(_ => Value);
    }

    public C.AuthProxy Value { get; }

    public IOptionsMonitor<C.AuthProxy> Monitor { get; }

    public RsaSecurityKey ValidationKey { get; }
}
