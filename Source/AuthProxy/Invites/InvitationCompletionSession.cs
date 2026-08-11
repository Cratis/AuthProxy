// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// The authenticated-session evidence offered for an invitation exchange.
/// </summary>
/// <param name="Succeeded">Whether the session authenticated successfully.</param>
/// <param name="Principal">The authenticated principal the invitation would be completed with.</param>
/// <param name="Properties">The authentication properties that establish the session.</param>
/// <param name="AuthenticatedAt">The instant the session was authenticated.</param>
/// <remarks>
/// The two callers of <see cref="IInviteCompletion"/> hold this evidence in different shapes. The post-login
/// middleware reads the established cookie session, whose properties carry the framework-stamped issue
/// instant. The provider callback holds the freshly received ticket instead — its properties are the
/// round-tripped challenge properties, which no handler has stamped yet, so the callback supplies the moment
/// the ticket was received as the authentication instant: that is literally when this authentication
/// happened.
/// </remarks>
sealed record InvitationCompletionSession(
    bool Succeeded,
    ClaimsPrincipal? Principal,
    AuthenticationProperties? Properties,
    DateTimeOffset? AuthenticatedAt);
