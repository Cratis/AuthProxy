// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Binds an AuthProxy-authored invitation transaction to the provider authentication round-trip.
/// </summary>
public static class InvitationAuthenticationState
{
    /// <summary>
    /// The authentication-properties key for the invitation transaction.
    /// </summary>
    public const string TransactionStateKey = "Cratis.AuthProxy.InvitationTransaction";

    /// <summary>
    /// The authentication-properties key for the independent invitation challenge.
    /// </summary>
    public const string ChallengeStateKey = "Cratis.AuthProxy.InvitationChallenge";

    /// <summary>
    /// The authentication-properties key for the exact invitation capability hash.
    /// </summary>
    public const string CapabilityHashStateKey = "Cratis.AuthProxy.InvitationCapabilityHash";

    /// <summary>
    /// The authentication-properties key recording the exact invitation capability a session has already
    /// completed the exchange for.
    /// </summary>
    public const string CompletedCapabilityHashStateKey = "Cratis.AuthProxy.InvitationCompletedCapabilityHash";

    /// <summary>
    /// Adds protected pending-invitation values to provider challenge properties when an invitation is in progress.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="properties">The provider challenge properties.</param>
    /// <returns><see langword="true"/> when no invitation is pending or valid invitation state was bound; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// A pending invitation always binds its capability, staged or not. That binding is the only thing that
    /// later tells the post-login exchange that the session coming back was established by <em>this</em>
    /// invitation's own challenge — a deployment that has not enabled the attested protocol stages nothing,
    /// and without it the exchange cannot tell the identity the person just authenticated with apart from
    /// whatever session the browser was already carrying.
    /// </remarks>
    public static bool TryBindPendingInvitation(HttpContext context, AuthenticationProperties properties)
    {
        if (!context.Request.Cookies.TryGetValue(Cookies.InvitationEntryState, out var protectedState))
        {
            if (context.TryGetPendingInvitationToken(out var pendingInvitation))
            {
                BindCapability(properties, pendingInvitation);
            }

            return true;
        }

        var protector = context.RequestServices.GetService<IInvitationEntryStateProtector>();
        if (protector is null
            || !protector.TryUnprotect(protectedState, out var state)
            || state.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            return false;
        }

        Bind(properties, state);
        return true;
    }

    /// <summary>
    /// Binds AuthProxy-authored invitation state to protected authentication properties.
    /// </summary>
    /// <param name="properties">The properties to bind.</param>
    /// <param name="state">The invitation state.</param>
    internal static void Bind(AuthenticationProperties properties, InvitationEntryState state)
    {
        properties.Items[TransactionStateKey] = state.InvitationTransaction;
        properties.Items[ChallengeStateKey] = state.InvitationChallenge;
        properties.Items[CapabilityHashStateKey] = state.CapabilityHash;
    }

    /// <summary>
    /// Binds the exact invitation capability a provider challenge is being started for.
    /// </summary>
    /// <param name="properties">The provider challenge properties.</param>
    /// <param name="invitationToken">The invitation capability the challenge answers.</param>
    internal static void BindCapability(AuthenticationProperties properties, string invitationToken) =>
        properties.Items[CapabilityHashStateKey] = ComputeCapabilityHash(invitationToken);

    /// <summary>
    /// Determines whether an authenticated session was established by the challenge started for one exact
    /// invitation capability.
    /// </summary>
    /// <param name="properties">The properties of the session authenticating the request.</param>
    /// <param name="invitationToken">The pending invitation capability.</param>
    /// <returns><see langword="true"/> when the session answers that exact capability; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// Properties travel inside the protected authentication ticket, so a value found here was put there by
    /// AuthProxy when it started the challenge and returned by the provider with the session that challenge
    /// established. A session that predates the invitation carries nothing, which is the answer that matters:
    /// it is not evidence of anything about this invitation.
    /// </remarks>
    internal static bool WasEstablishedFor(AuthenticationProperties? properties, string invitationToken) =>
        properties is not null
        && properties.Items.TryGetValue(CapabilityHashStateKey, out var boundCapabilityHash)
        && !string.IsNullOrEmpty(boundCapabilityHash)
        && FixedTimeEquals(ComputeCapabilityHash(invitationToken), boundCapabilityHash);

    /// <summary>
    /// Records on a session's authentication properties that its invitation exchange has completed, so no
    /// later request can run the exchange for the same capability again.
    /// </summary>
    /// <param name="properties">The properties of the session that completed the invitation.</param>
    /// <param name="invitationToken">The invitation capability that was completed.</param>
    /// <remarks>
    /// The pending binding is replaced rather than kept alongside the completion record: a capability that
    /// has been exchanged is no longer pending, and a session still claiming to have been established
    /// <em>for</em> it would re-run the exchange the moment a stale pending-invitation cookie replays — the
    /// application answers that with a duplicate-subject conflict for an invitation that actually succeeded.
    /// </remarks>
    internal static void MarkCompleted(AuthenticationProperties properties, string invitationToken)
    {
        properties.Items.Remove(TransactionStateKey);
        properties.Items.Remove(ChallengeStateKey);
        properties.Items.Remove(CapabilityHashStateKey);
        properties.Items[CompletedCapabilityHashStateKey] = ComputeCapabilityHash(invitationToken);
    }

    /// <summary>
    /// Determines whether a session has already completed the exchange for one exact invitation capability.
    /// </summary>
    /// <param name="properties">The properties of the session authenticating the request.</param>
    /// <param name="invitationToken">The invitation capability being offered.</param>
    /// <returns><see langword="true"/> when the session already completed that exact capability; otherwise <see langword="false"/>.</returns>
    internal static bool WasCompletedFor(AuthenticationProperties? properties, string invitationToken) =>
        properties is not null
        && properties.Items.TryGetValue(CompletedCapabilityHashStateKey, out var completedCapabilityHash)
        && !string.IsNullOrEmpty(completedCapabilityHash)
        && FixedTimeEquals(ComputeCapabilityHash(invitationToken), completedCapabilityHash);

    /// <summary>
    /// Computes the hash that identifies one exact invitation capability.
    /// </summary>
    /// <param name="invitationToken">The invitation capability.</param>
    /// <returns>The capability hash.</returns>
    internal static string ComputeCapabilityHash(string invitationToken) =>
        Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(invitationToken)));

    /// <summary>
    /// Determines whether authentication properties carry a complete protected invitation binding.
    /// </summary>
    /// <param name="properties">The provider authentication properties.</param>
    /// <returns><see langword="true"/> when all invitation-binding values are present; otherwise <see langword="false"/>.</returns>
    internal static bool IsBound(AuthenticationProperties? properties) =>
        properties is not null
        && properties.Items.TryGetValue(TransactionStateKey, out var transaction)
        && !string.IsNullOrWhiteSpace(transaction)
        && properties.Items.TryGetValue(ChallengeStateKey, out var challenge)
        && !string.IsNullOrWhiteSpace(challenge)
        && properties.Items.TryGetValue(CapabilityHashStateKey, out var capabilityHash)
        && !string.IsNullOrWhiteSpace(capabilityHash);

    /// <summary>
    /// Determines whether returned provider properties carry the exact staged invitation binding.
    /// </summary>
    /// <param name="state">The protected browser state.</param>
    /// <param name="properties">The returned provider properties.</param>
    /// <returns><see langword="true"/> when all opaque bindings match; otherwise <see langword="false"/>.</returns>
    internal static bool Matches(InvitationEntryState state, AuthenticationProperties? properties) =>
        properties is not null
        && properties.Items.TryGetValue(TransactionStateKey, out var transaction)
        && properties.Items.TryGetValue(ChallengeStateKey, out var challenge)
        && properties.Items.TryGetValue(CapabilityHashStateKey, out var capabilityHash)
        && FixedTimeEquals(state.InvitationTransaction, transaction)
        && FixedTimeEquals(state.InvitationChallenge, challenge)
        && FixedTimeEquals(state.CapabilityHash, capabilityHash);

    static bool FixedTimeEquals(string expected, string? actual)
    {
        if (actual is null)
        {
            return false;
        }

        var expectedBytes = Encoding.UTF8.GetBytes(expected);
        var actualBytes = Encoding.UTF8.GetBytes(actual);
        return CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
    }
}
