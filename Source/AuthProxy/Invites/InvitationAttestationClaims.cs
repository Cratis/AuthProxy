// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Defines the claims AuthProxy writes to signed invitation attestations.
/// </summary>
public static class InvitationAttestationClaims
{
    /// <summary>
    /// The claim that distinguishes staging from completion.
    /// </summary>
    public const string Purpose = "purpose";

    /// <summary>
    /// The tenant that owns the invitation.
    /// </summary>
    public const string TenantId = "tenant_id";

    /// <summary>
    /// The identifier of the invitation capability.
    /// </summary>
    public const string InvitationId = "invitation_id";

    /// <summary>
    /// The opaque identifier of the current invitation transaction.
    /// </summary>
    public const string InvitationTransaction = "invitation_transaction";

    /// <summary>
    /// The independent opaque challenge bound to provider authentication.
    /// </summary>
    public const string InvitationChallenge = "invitation_challenge";

    /// <summary>
    /// The base64url-encoded SHA-256 hash of the exact invitation capability.
    /// </summary>
    public const string CapabilityHash = "capability_hash";

    /// <summary>
    /// The configured canonical provider key.
    /// </summary>
    public const string ProviderKey = "provider_key";

    /// <summary>
    /// The normalized provider issuer.
    /// </summary>
    public const string ProviderIssuer = "provider_issuer";

    /// <summary>
    /// The provider subject.
    /// </summary>
    public const string ProviderSubject = "provider_subject";

    /// <summary>
    /// The verified provider-derived email address, present only for email-targeted completion.
    /// </summary>
    public const string Email = "email";

    /// <summary>
    /// The provider-derived email-verification result, present only for email-targeted completion.
    /// </summary>
    public const string EmailVerified = "email_verified";

    /// <summary>
    /// The provider-derived authentication assurance.
    /// </summary>
    public const string Assurance = "assurance";

    /// <summary>
    /// The time at which the provider authentication completed.
    /// </summary>
    public const string AuthenticatedAt = "authenticated_at";

    /// <summary>
    /// The purpose value for a pre-authentication staging call.
    /// </summary>
    public const string StagePurpose = "invite-stage";

    /// <summary>
    /// The purpose value for a post-authentication completion call.
    /// </summary>
    public const string CompletePurpose = "invite-complete";
}
