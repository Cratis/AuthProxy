// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Issues short-lived RS256 invitation attestations from validated AuthProxy state.
/// </summary>
/// <param name="configuration">The current AuthProxy configuration.</param>
/// <param name="timeProvider">The source of the current time.</param>
public sealed class InvitationAttestationIssuer(IOptionsMonitor<C.AuthProxy> configuration, TimeProvider timeProvider) : IInvitationAttestationIssuer
{
    /// <inheritdoc />
    public bool TryIssueStage(InvitationEntryState state, out string attestation) =>
        TryIssue(
            state,
            new Dictionary<string, object>
            {
                [InvitationAttestationClaims.Purpose] = InvitationAttestationClaims.StagePurpose,
            },
            out attestation);

    /// <inheritdoc />
    public bool TryIssueComplete(InvitationEntryState state, InvitationVerifiedIdentity identity, out string attestation)
    {
        var claims = new Dictionary<string, object>
        {
            [InvitationAttestationClaims.Purpose] = InvitationAttestationClaims.CompletePurpose,
            [InvitationAttestationClaims.ProviderKey] = identity.ProviderKey,
            [InvitationAttestationClaims.ProviderIssuer] = identity.ProviderIssuer,
            [InvitationAttestationClaims.ProviderSubject] = identity.ProviderSubject,
            [InvitationAttestationClaims.Assurance] = identity.Assurance,
            [InvitationAttestationClaims.AuthenticatedAt] = identity.AuthenticatedAt.ToUnixTimeSeconds(),
        };
        if (identity.Email is not null)
        {
            claims[InvitationAttestationClaims.Email] = identity.Email;
            claims[InvitationAttestationClaims.EmailVerified] = true;
        }

        return TryIssue(state, claims, out attestation);
    }

    /// <summary>
    /// Creates a cryptographically random 256-bit opaque value.
    /// </summary>
    /// <returns>A base64url-encoded opaque value.</returns>
    internal static string CreateOpaqueValue()
    {
        Span<byte> value = stackalloc byte[32];
        RandomNumberGenerator.Fill(value);
        return Base64UrlEncoder.Encode(value.ToArray());
    }

    static bool TryCreateSigningCredentials(C.InvitationAttestationSigningKey key, out SigningCredentials credentials)
    {
        credentials = default!;
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(key.PrivateKeyPem);
            var securityKey = new RsaSecurityKey(rsa.ExportParameters(true)) { KeyId = key.KeyId };
            credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);
            return true;
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException)
        {
            return false;
        }
    }

    bool TryIssue(InvitationEntryState state, Dictionary<string, object> claims, out string attestation)
    {
        attestation = string.Empty;
        var settings = configuration.CurrentValue.Invite?.Attestation;
        if (settings is null)
        {
            return false;
        }

        var key = settings.SigningKeys.SingleOrDefault(_ =>
            string.Equals(_.KeyId, settings.ActiveKeyId, StringComparison.Ordinal));
        if (key is null || !TryCreateSigningCredentials(key, out var credentials))
        {
            return false;
        }

        claims[JwtRegisteredClaimNames.Jti] = CreateOpaqueValue();
        claims[InvitationAttestationClaims.TenantId] = state.TenantId;
        claims[InvitationAttestationClaims.InvitationId] = state.InvitationId;
        claims[InvitationAttestationClaims.InvitationTransaction] = state.InvitationTransaction;
        claims[InvitationAttestationClaims.InvitationChallenge] = state.InvitationChallenge;
        claims[InvitationAttestationClaims.CapabilityHash] = state.CapabilityHash;

        var now = timeProvider.GetUtcNow();
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = settings.Issuer,
            Audience = settings.Audience,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = now.Add(settings.Lifetime).UtcDateTime,
            Claims = claims,
            SigningCredentials = credentials,
        };

        attestation = new JsonWebTokenHandler().CreateToken(descriptor);
        return true;
    }
}
