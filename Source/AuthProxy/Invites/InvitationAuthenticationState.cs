// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication;

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
    /// Adds protected pending-invitation values to provider challenge properties when an invitation is in progress.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="properties">The provider challenge properties.</param>
    /// <returns><see langword="true"/> when no invitation is pending or valid invitation state was bound; otherwise <see langword="false"/>.</returns>
    public static bool TryBindPendingInvitation(HttpContext context, AuthenticationProperties properties)
    {
        if (!context.Request.Cookies.TryGetValue(Cookies.InvitationEntryState, out var protectedState))
        {
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
