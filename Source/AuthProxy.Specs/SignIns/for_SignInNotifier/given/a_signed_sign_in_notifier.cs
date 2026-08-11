// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

/// <summary>
/// A notifier wired exactly as the host wires it once <c>SignIn:Attestation</c> is configured — the same
/// released notifier, with the envelope signer available to it.
/// </summary>
public class a_signed_sign_in_notifier : a_sign_in_notifier
{
    protected const string Issuer = "https://auth.example.com";
    protected const string Audience = "ada";
    protected const string KeyId = "sign-in-2026-08";

    protected static readonly string SigningKeyPem = CreatePrivateKeyPem();
    protected static readonly RsaSecurityKey ValidationKey = CreateValidationKey(SigningKeyPem);

    protected DateTimeOffset _now;

    protected virtual string ConfiguredNotifyUrl => NotifyUrl;

    protected virtual string ConfiguredSigningKeyPem => SigningKeyPem;

    protected virtual bool SignerIsAvailable => true;

    protected virtual C.SignInAttestation? CreateAttestation() => new()
    {
        Issuer = Issuer,
        Audience = Audience,
        ActiveKeyId = KeyId,
        Lifetime = TimeSpan.FromSeconds(60),
        SigningKeys =
        [
            new C.SignInAttestationSigningKey
            {
                KeyId = KeyId,
                PrivateKeyPem = ConfiguredSigningKeyPem,
            }
        ],
    };

    protected override C.AuthProxy CreateConfig() => new()
    {
        SignIn = new C.SignIn
        {
            NotifyUrl = ConfiguredNotifyUrl,
            Attestation = CreateAttestation(),
        }
    };

    protected override SignInNotifier CreateNotifier(
        C.AuthProxy configuration,
        IOptionsMonitor<C.AuthProxy> optionsMonitor,
        IHttpClientFactory httpClientFactory)
    {
        _now = DateTimeOffset.FromUnixTimeSeconds(TimeProvider.System.GetUtcNow().ToUnixTimeSeconds());
        return SignerIsAvailable
            ? new(
                optionsMonitor,
                new ClientLocationResolver(),
                httpClientFactory,
                Substitute.For<ILogger<SignInNotifier>>(),
                null,
                new SignInNotificationSigner(optionsMonitor, new FixedTimeProvider(_now)))
            : new(
                optionsMonitor,
                new ClientLocationResolver(),
                httpClientFactory,
                Substitute.For<ILogger<SignInNotifier>>());
    }

    /// <summary>
    /// Posts the very same sign-in through the released four-argument notifier, which has no signer and no
    /// attestation configuration at all. Its recorded request is what "today's behavior" means, byte for byte.
    /// </summary>
    /// <returns>The handler that recorded the released notifier's request.</returns>
    protected async Task<RecordingHttpMessageHandler> NotifyThroughTheReleasedNotifier()
    {
        var handler = new RecordingHttpMessageHandler();
        var options = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        options.CurrentValue.Returns(new C.AuthProxy { SignIn = new C.SignIn { NotifyUrl = NotifyUrl } });
        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(handler));

        var released = new SignInNotifier(
            options,
            new ClientLocationResolver(),
            httpClientFactory,
            Substitute.For<ILogger<SignInNotifier>>());
        await released.Notify(_httpContext, _principal);
        return handler;
    }

    protected async Task<TokenValidationResult> Validate(
        string envelope,
        string issuer = Issuer,
        string audience = Audience) =>
        await new JsonWebTokenHandler().ValidateTokenAsync(envelope, new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = ValidationKey,
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
        });

    protected static JsonWebToken Read(string envelope) => new JsonWebTokenHandler().ReadJsonWebToken(envelope);

    protected static string Claim(JsonWebToken envelope, string type) => envelope.Claims.Single(_ => _.Type == type).Value;

    protected static string Digest(byte[] body) => Base64UrlEncoder.Encode(SHA256.HashData(body));

    static string CreatePrivateKeyPem()
    {
        using var rsa = RSA.Create(2048);
        return rsa.ExportPkcs8PrivateKeyPem();
    }

    static RsaSecurityKey CreateValidationKey(string privateKeyPem)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);
        return new RsaSecurityKey(rsa.ExportParameters(false)) { KeyId = KeyId };
    }

    sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
