// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Attestations;
using Microsoft.Extensions.Options;
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
    internal static string CreateOpaqueValue() => AttestationSigner.CreateOpaqueValue();

    bool TryIssue(InvitationEntryState state, Dictionary<string, object> claims, out string attestation)
    {
        attestation = string.Empty;
        var settings = configuration.CurrentValue.Invite?.Attestation;
        if (settings is null)
        {
            return false;
        }

        // FirstOrDefault, not SingleOrDefault: a configuration that slipped a duplicate key identifier past
        // startup validation must degrade to a refusal to issue, never to an exception thrown out of a request.
        var key = settings.SigningKeys.FirstOrDefault(_ =>
            string.Equals(_.KeyId, settings.ActiveKeyId, StringComparison.Ordinal));
        if (key is null)
        {
            return false;
        }

        claims[InvitationAttestationClaims.TenantId] = state.TenantId;
        claims[InvitationAttestationClaims.InvitationId] = state.InvitationId;
        claims[InvitationAttestationClaims.InvitationTransaction] = state.InvitationTransaction;
        claims[InvitationAttestationClaims.InvitationChallenge] = state.InvitationChallenge;
        claims[InvitationAttestationClaims.CapabilityHash] = state.CapabilityHash;

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
