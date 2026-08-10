// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Represents the identity-free request AuthProxy sends while completing an invitation.
/// </summary>
/// <param name="InvitationTransaction">The AuthProxy-authored transaction.</param>
sealed record InvitationCompleteRequest(string InvitationTransaction);
