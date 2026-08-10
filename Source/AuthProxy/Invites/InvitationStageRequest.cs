// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Represents the bounded request AuthProxy sends while staging an invitation capability.
/// </summary>
/// <param name="InvitationTransaction">The AuthProxy-authored transaction.</param>
/// <param name="InvitationToken">The exact signed invitation capability.</param>
/// <param name="InvitationChallenge">The independent AuthProxy-authored challenge.</param>
sealed record InvitationStageRequest(
    string InvitationTransaction,
    string InvitationToken,
    string InvitationChallenge);
