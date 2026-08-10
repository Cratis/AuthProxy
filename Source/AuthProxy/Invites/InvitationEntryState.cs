// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Represents AuthProxy-authored state for one staged invitation entry.
/// </summary>
/// <param name="TenantId">The tenant that owns the invitation.</param>
/// <param name="InvitationId">The invitation capability identifier.</param>
/// <param name="InvitationTransaction">The opaque transaction identifier.</param>
/// <param name="InvitationChallenge">The independent opaque authentication challenge.</param>
/// <param name="CapabilityHash">The hash of the exact invitation capability.</param>
/// <param name="ExpiresAt">The time at which the protected browser state expires.</param>
public sealed record InvitationEntryState(
    string TenantId,
    string InvitationId,
    string InvitationTransaction,
    string InvitationChallenge,
    string CapabilityHash,
    DateTimeOffset ExpiresAt);
