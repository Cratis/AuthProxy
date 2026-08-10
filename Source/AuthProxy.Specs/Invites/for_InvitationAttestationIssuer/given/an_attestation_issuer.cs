// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Invites.for_InvitationAttestationIssuer.given;

public class an_attestation_issuer : Specification
{
    protected const string Issuer = "https://auth.example.com";
    protected const string Audience = "ada-lobby";
    protected const string KeyId = "invite-2026-08";
    protected const string TenantId = "hive-consulting";
    protected const string InvitationId = "invite-42";
    protected const string Transaction = "transaction-value";
    protected const string Challenge = "challenge-value";
    protected const string CapabilityHash = "capability-hash";

    protected InvitationAttestationIssuer _issuer;
    protected InvitationEntryState _state;
    protected RsaSecurityKey _validationKey;
    protected DateTimeOffset _now;
    protected IOptionsMonitor<C.AuthProxy> _options;
    protected C.AuthProxy _configuration;

    void Establish()
    {
        using var rsa = RSA.Create(2048);
        var privateKeyPem = rsa.ExportPkcs8PrivateKeyPem();
        _validationKey = new RsaSecurityKey(rsa.ExportParameters(false)) { KeyId = KeyId };
        _now = DateTimeOffset.FromUnixTimeSeconds(TimeProvider.System.GetUtcNow().ToUnixTimeSeconds());

        _options = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        _configuration = new C.AuthProxy
        {
            Invite = new C.Invite
            {
                Attestation = new C.InvitationAttestation
                {
                    Issuer = Issuer,
                    Audience = Audience,
                    ActiveKeyId = KeyId,
                    Lifetime = TimeSpan.FromSeconds(60),
                    SigningKeys =
                    [
                        new C.InvitationAttestationSigningKey
                        {
                            KeyId = KeyId,
                            PrivateKeyPem = privateKeyPem,
                        }
                    ],
                }
            }
        };
        _options.CurrentValue.Returns(_configuration);

        _issuer = new(_options, new FixedTimeProvider(_now));
        _state = new(TenantId, InvitationId, Transaction, Challenge, CapabilityHash, _now.AddMinutes(15));
    }

    protected async Task<TokenValidationResult> Validate(
        string token,
        SecurityKey? validationKey = null,
        string issuer = Issuer,
        string audience = Audience) =>
        await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = validationKey ?? _validationKey,
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
        });

    protected static JsonWebToken Read(string token) => new JsonWebTokenHandler().ReadJsonWebToken(token);

    sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
