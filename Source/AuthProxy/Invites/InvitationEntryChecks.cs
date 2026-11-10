// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.IdentityModel.JsonWebTokens;
using static Cratis.AuthProxy.Invites.InvitationClaimReader;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// The checks of an attested invitation's entry-state guard chain that depend only on the presented capability
/// and the unprotected entry state.
/// </summary>
static class InvitationEntryChecks
{
    /// <summary>
    /// Validates that the unprotected entry state belongs to the presented capability: unexpired, bound to the
    /// capability's hash, and naming the capability's invitation id.
    /// </summary>
    /// <param name="entryState">The unprotected invitation-entry state.</param>
    /// <param name="inviteToken">The invitation capability presented on the request.</param>
    /// <returns>The first failed check's reason, or <see cref="InvitationCompletionFailureReason.None"/> when all pass.</returns>
    internal static InvitationCompletionFailureReason ValidateEntryCapability(InvitationEntryState entryState, string inviteToken)
    {
        if (entryState.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            return InvitationCompletionFailureReason.EntryStateExpired;
        }

        if (!FixedTimeEquals(entryState.CapabilityHash, InvitationAuthenticationState.ComputeCapabilityHash(inviteToken)))
        {
            return InvitationCompletionFailureReason.CapabilityHashMismatch;
        }

        if (!TryGetSingleTokenClaim(inviteToken, JwtRegisteredClaimNames.Jti, out var invitationId))
        {
            return InvitationCompletionFailureReason.InvitationIdClaimInvalid;
        }

        if (!FixedTimeEquals(entryState.InvitationId, invitationId))
        {
            return InvitationCompletionFailureReason.InvitationIdMismatch;
        }

        return InvitationCompletionFailureReason.None;
    }

    /// <summary>
    /// Resolves the recipient mode the invitation token names: an identity-bound recipient, or an email-targeted
    /// recipient whose invited address must be a single well-formed email claim.
    /// </summary>
    /// <param name="inviteToken">The invitation capability presented on the request.</param>
    /// <param name="invite">The resolved invite configuration.</param>
    /// <param name="recipient">The resolved recipient when the recipient mode is valid.</param>
    /// <returns><see langword="true"/> when the recipient mode is valid; otherwise <see langword="false"/>.</returns>
    internal static bool TryResolveRecipient(string inviteToken, C.Invite invite, out InvitationRecipient recipient)
    {
        recipient = default;
        if (!InviteMiddleware.TryResolveRecipientMode(inviteToken, invite.EmailClaim, out var recipientProviderKey))
        {
            return false;
        }

        var invitedEmail = string.Empty;
        if (string.IsNullOrEmpty(recipientProviderKey)
            && !TryGetInvitedEmailAddress(inviteToken, invite.EmailClaim, out invitedEmail))
        {
            return false;
        }

        recipient = new InvitationRecipient(recipientProviderKey, invitedEmail);
        return true;
    }

    static bool TryGetInvitedEmailAddress(string inviteToken, string emailClaim, out string invitedEmail) =>
        TryGetSingleTokenClaim(inviteToken, emailClaim, out invitedEmail)
        && InviteMiddleware.IsAnEmailAddress(invitedEmail);
}
