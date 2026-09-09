// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Names the guard that stopped an attested invitation completion before the downstream exchange call, for
/// operator diagnosis. Every member names a stage or predicate only - never a token, email, subject,
/// capability hash, transaction, challenge, or other raw claim value.
/// </summary>
internal enum InvitationCompletionFailureReason
{
    /// <summary>No failure occurred.</summary>
    None = 0,

    /// <summary>The attested protocol's required collaborators are not fully configured for this request.</summary>
    ProtocolMisconfigured = 1,

    /// <summary>The invitation capability exceeds the maximum accepted length.</summary>
    CapabilityTokenTooLong = 2,

    /// <summary>The protected invitation-entry state cookie was not presented or did not unprotect.</summary>
    EntryStateUnprotectFailed = 3,

    /// <summary>The protected invitation-entry state has expired.</summary>
    EntryStateExpired = 4,

    /// <summary>The presented capability does not hash to the one the entry state was staged for.</summary>
    CapabilityHashMismatch = 5,

    /// <summary>The capability's invitation identifier claim did not occur exactly once with an acceptable value.</summary>
    InvitationIdClaimInvalid = 6,

    /// <summary>The capability's invitation identifier does not match the staged entry state.</summary>
    InvitationIdMismatch = 7,

    /// <summary>No tenant claim is configured for invitation completion.</summary>
    TenantClaimNotConfigured = 8,

    /// <summary>The capability's tenant claim did not occur exactly once with an acceptable value.</summary>
    TenantClaimInvalid = 9,

    /// <summary>The capability's tenant claim does not match the staged entry state.</summary>
    TenantIdMismatch = 10,

    /// <summary>The capability's recipient mode (email-targeted or identity-bound) could not be resolved.</summary>
    RecipientModeInvalid = 11,

    /// <summary>The tenant resolved for the current request does not match the capability's tenant.</summary>
    RequestTenantMismatch = 12,

    /// <summary>The evidence session backing this callback or request was not established.</summary>
    SessionNotEstablished = 13,

    /// <summary>The session's authentication properties do not carry the exact staged challenge binding.</summary>
    ChallengeBindingMismatch = 14,

    /// <summary>The authenticated request carried no principal.</summary>
    PrincipalMissing = 15,

    /// <summary>The provider that authenticated the principal has no canonical identity configuration.</summary>
    CanonicalIdentityNotConfigured = 16,

    /// <summary>Canonical identity resolution failed against malformed, missing, duplicate, or conflicting claims.</summary>
    CanonicalIdentityResolutionFailed = 17,

    /// <summary>Zero or more than one configured provider matches the resolved canonical provider key.</summary>
    ProviderConfigurationAmbiguous = 18,

    /// <summary>The provider-supplied authentication assurance or authentication-time evidence is unavailable.</summary>
    AssuranceEvidenceUnavailable = 19,

    /// <summary>The provider has not been enabled for email-targeted invitation completion.</summary>
    EmailCompletionDisabledForProvider = 20,

    /// <summary>The provider has not been enabled for identity-bound invitation completion.</summary>
    IdentityBindingCompletionDisabled = 21,

    /// <summary>The authenticated provider does not match the capability's bound identity provider.</summary>
    IdentityBindingProviderMismatch = 22,

    /// <summary>The completion attestation could not be issued.</summary>
    AttestationIssuanceFailed = 23,
}
