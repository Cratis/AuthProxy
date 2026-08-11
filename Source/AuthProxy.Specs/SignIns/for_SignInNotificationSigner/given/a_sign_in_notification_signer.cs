// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.SignIns.for_SignInNotificationSigner.given;

public class a_sign_in_notification_signer : Specification
{
    protected const string Issuer = "https://auth.example.com";
    protected const string Audience = "ada";
    protected const string KeyId = "sign-in-2026-08";

    /// <summary>A target carrying a query and a fragment, so the RFC 9449 <c>htu</c> spelling is observable.</summary>
    protected static readonly Uri Target = new("https://studio.example.com/api/internal/sign-ins?trace=1#frag");

    protected static readonly byte[] Body = Encoding.UTF8.GetBytes("{\"subject\":\"subject-123\"}");

    protected SignInNotificationSigner _signer;
    protected C.AuthProxy _configuration;
    protected RsaSecurityKey _validationKey;
    protected RsaSecurityKey _unrelatedKey;
    protected DateTimeOffset _now;

    protected virtual TimeSpan Lifetime => TimeSpan.FromSeconds(60);

    protected virtual DateTimeOffset IssuedAt => _now;

    protected virtual string ActiveKeyId => KeyId;

    protected virtual string PrivateKeyPem(string valid) => valid;

    protected virtual bool SigningIsConfigured => true;

    void Establish()
    {
        using var rsa = RSA.Create(2048);
        using var unrelated = RSA.Create(2048);
        _validationKey = new RsaSecurityKey(rsa.ExportParameters(false)) { KeyId = KeyId };
        _unrelatedKey = new RsaSecurityKey(unrelated.ExportParameters(false)) { KeyId = KeyId };
        _now = DateTimeOffset.FromUnixTimeSeconds(TimeProvider.System.GetUtcNow().ToUnixTimeSeconds());

        _configuration = new C.AuthProxy
        {
            SignIn = new C.SignIn
            {
                NotifyUrl = Target.ToString(),
                Attestation = SigningIsConfigured
                    ? new C.SignInAttestation
                    {
                        Issuer = Issuer,
                        Audience = Audience,
                        ActiveKeyId = ActiveKeyId,
                        Lifetime = Lifetime,
                        SigningKeys =
                        [
                            new C.SignInAttestationSigningKey
                            {
                                KeyId = KeyId,
                                PrivateKeyPem = PrivateKeyPem(rsa.ExportPkcs8PrivateKeyPem()),
                            }
                        ],
                    }
                    : null,
            }
        };

        var options = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        options.CurrentValue.Returns(_configuration);
        _signer = new(options, new FixedTimeProvider(IssuedAt));
    }

    protected async Task<TokenValidationResult> Validate(
        string envelope,
        SecurityKey? validationKey = null,
        string issuer = Issuer,
        string audience = Audience,
        TimeSpan? clockSkew = null) =>
        await new JsonWebTokenHandler().ValidateTokenAsync(envelope, new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = validationKey ?? _validationKey,
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateLifetime = true,
            ClockSkew = clockSkew ?? TimeSpan.Zero,
        });

    protected static JsonWebToken Read(string envelope) => new JsonWebTokenHandler().ReadJsonWebToken(envelope);

    protected static string Claim(JsonWebToken envelope, string type) => envelope.Claims.Single(_ => _.Type == type).Value;

    protected static string Digest(byte[] body) => Base64UrlEncoder.Encode(SHA256.HashData(body));

    sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
