// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;
using Cratis.AuthProxy.Attestations;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.OnBehalfSessions;

/// <summary>
/// Issues the short-lived RS256 tokens that authenticate AuthProxy to the application during on-behalf sessions.
/// </summary>
/// <param name="configuration">The current AuthProxy configuration.</param>
/// <param name="timeProvider">The source of the current time.</param>
/// <remarks>
/// Provenance, audience, time and replay come from <see cref="AttestationSigner"/> — the one signing implementation,
/// shared with sign-in and invitation attestation. Every token states who is acting (<c language="text">act</c>), for whom
/// (<c language="text">sub</c>), in which tenant, for which issue and in which session, so an application never has to
/// take any of that from an unsigned header or query parameter. A call is additionally bound to its route and body,
/// and a forwarded request to the exact identity header values it travels with.
/// </remarks>
public sealed class OnBehalfAttestations(IOptionsMonitor<C.AuthProxy> configuration, TimeProvider timeProvider) : IOnBehalfAttestations
{
    /// <inheritdoc />
    public bool TryIssueForCall(string purpose, OnBehalfSession session, HttpMethod method, Uri target, byte[] body, out string token)
    {
        var claims = ClaimsFor(purpose, session);
        claims[OnBehalfAttestationClaims.HttpMethod] = method.Method;
        claims[OnBehalfAttestationClaims.HttpUri] = target.GetLeftPart(UriPartial.Path);
        claims[OnBehalfAttestationClaims.BodyHash] = Digest(body);
        return TryIssue(claims, out token);
    }

    /// <inheritdoc />
    public bool TryIssueForForward(OnBehalfSession session, string principalHeader, string actorHeader, out string token)
    {
        var claims = ClaimsFor(OnBehalfAttestationClaims.ForwardPurpose, session);
        claims[OnBehalfAttestationClaims.PrincipalHash] = Digest(Encoding.ASCII.GetBytes(principalHeader));
        claims[OnBehalfAttestationClaims.ActorHash] = Digest(Encoding.ASCII.GetBytes(actorHeader));
        return TryIssue(claims, out token);
    }

    static Dictionary<string, object> ClaimsFor(string purpose, OnBehalfSession session) => new(StringComparer.Ordinal)
    {
        [OnBehalfAttestationClaims.Purpose] = purpose,
        [OnBehalfAttestationClaims.Subject] = session.Subject,
        [OnBehalfAttestationClaims.Actor] = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [OnBehalfAttestationClaims.ActorSubject] = session.Actor.UserId,
            [OnBehalfAttestationClaims.ActorIdentityProvider] = session.Actor.IdentityProvider,
        },
        [OnBehalfAttestationClaims.Tenant] = session.Tenant,
        [OnBehalfAttestationClaims.Issue] = session.Issue,
        [OnBehalfAttestationClaims.SessionId] = session.SessionId,
    };

    static string Digest(byte[] value) => Base64UrlEncoder.Encode(SHA256.HashData(value));

    bool TryIssue(Dictionary<string, object> claims, out string token)
    {
        token = string.Empty;
        var settings = configuration.CurrentValue.OnBehalf?.Attestation;
        if (settings is null)
        {
            return false;
        }

        // FirstOrDefault, not SingleOrDefault: a duplicate key identifier that slipped past startup validation must
        // degrade to a refusal to sign, never to an exception thrown out of a request.
        var key = settings.SigningKeys.FirstOrDefault(_ => string.Equals(_.KeyId, settings.ActiveKeyId, StringComparison.Ordinal));
        if (key is null)
        {
            return false;
        }

        return AttestationSigner.TryIssue(
            new AttestationSigningContract(settings.Issuer, settings.Audience, key.KeyId, key.PrivateKeyPem, settings.Lifetime),
            timeProvider.GetUtcNow(),
            claims,
            out token);
    }
}
