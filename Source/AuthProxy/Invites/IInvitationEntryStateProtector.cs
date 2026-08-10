// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Protects invitation state stored in the browser from disclosure and modification.
/// </summary>
public interface IInvitationEntryStateProtector
{
    /// <summary>
    /// Protects invitation state.
    /// </summary>
    /// <param name="state">The state to protect.</param>
    /// <returns>The protected value.</returns>
    string Protect(InvitationEntryState state);

    /// <summary>
    /// Tries to recover protected invitation state.
    /// </summary>
    /// <param name="protectedState">The protected value.</param>
    /// <param name="state">The recovered state when successful.</param>
    /// <returns><see langword="true"/> when the value is valid; otherwise <see langword="false"/>.</returns>
    bool TryUnprotect(string protectedState, out InvitationEntryState state);
}
