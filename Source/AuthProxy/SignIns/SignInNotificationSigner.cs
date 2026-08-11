// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Cratis.AuthProxy.Attestations;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.SignIns;

/// <summary>
/// Issues the short-lived RS256 envelope that authenticates one sign-in notification to the application.
/// </summary>
/// <param name="configuration">The current AuthProxy configuration.</param>
/// <param name="timeProvider">The source of the current time.</param>
/// <remarks>
/// The envelope binds six facts about the notification it accompanies, so that reaching the application's
/// private endpoint is no longer enough to choose which user it records as having signed in: provenance
/// (<c>iss</c> plus the <c>kid</c> header selecting the key), audience (<c>aud</c>), route
/// (<see cref="SignInAttestationClaims.HttpMethod"/> and <see cref="SignInAttestationClaims.HttpUri"/>), body
/// (<see cref="SignInAttestationClaims.BodyHash"/> over the exact bytes posted), time (<c>iat</c>, <c>nbf</c>,
/// <c>exp</c>) and replay (a random <c>jti</c>). Provenance, audience, time and replay come from
/// <see cref="AttestationSigner"/> — the one signing implementation, shared with invitation attestation — and
/// route and body are added here.
/// </remarks>
public sealed class SignInNotificationSigner(IOptionsMonitor<C.AuthProxy> configuration, TimeProvider timeProvider) : ISignInNotificationSigner
{
    /// <inheritdoc />
    public bool IsEnabled => configuration.CurrentValue.SignIn?.Attestation is not null;

    /// <inheritdoc />
    public bool TryIssue(HttpMethod method, Uri target, byte[] body, out string attestation)
    {
        attestation = string.Empty;
        var settings = configuration.CurrentValue.SignIn?.Attestation;
        if (settings is null)
        {
            return false;
        }

        var key = settings.SigningKeys.SingleOrDefault(_ =>
            string.Equals(_.KeyId, settings.ActiveKeyId, StringComparison.Ordinal));
        if (key is null)
        {
            return false;
        }

        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [SignInAttestationClaims.Purpose] = SignInAttestationClaims.NotificationPurpose,
            [SignInAttestationClaims.HttpMethod] = method.Method,
            [SignInAttestationClaims.HttpUri] = target.GetLeftPart(UriPartial.Path),
            [SignInAttestationClaims.BodyHash] = Base64UrlEncoder.Encode(SHA256.HashData(body)),
        };

        return AttestationSigner.TryIssue(
            new AttestationSigningContract(
                settings.Issuer,
                settings.Audience,
                key.KeyId,
                key.PrivateKeyPem,
                settings.Lifetime),
            timeProvider.GetUtcNow(),
            claims,
            out attestation);
    }
}
