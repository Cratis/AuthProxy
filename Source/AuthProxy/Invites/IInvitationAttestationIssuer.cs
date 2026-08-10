// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Issues AuthProxy-signed assertions for the two-stage invitation protocol.
/// </summary>
public interface IInvitationAttestationIssuer
{
    /// <summary>
    /// Tries to issue an attestation for the pre-authentication staging call.
    /// </summary>
    /// <param name="state">The AuthProxy-authored invitation state.</param>
    /// <param name="attestation">The compact signed JWT when successful.</param>
    /// <returns><see langword="true"/> when the attestation was issued; otherwise <see langword="false"/>.</returns>
    bool TryIssueStage(InvitationEntryState state, out string attestation);

    /// <summary>
    /// Tries to issue an attestation for the post-authentication completion call.
    /// </summary>
    /// <param name="state">The AuthProxy-authored invitation state.</param>
    /// <param name="identity">The verified provider identity.</param>
    /// <param name="attestation">The compact signed JWT when successful.</param>
    /// <returns><see langword="true"/> when the attestation was issued; otherwise <see langword="false"/>.</returns>
    bool TryIssueComplete(InvitationEntryState state, InvitationVerifiedIdentity identity, out string attestation);
}
