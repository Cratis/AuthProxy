// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Defines the one implementation of the invitation exchange — the call that hands a validated invitation
/// capability and the identity that answered its challenge to the invitation authority.
/// </summary>
/// <remarks>
/// Two callers complete invitations and must produce identical exchanges: <see cref="InviteMiddleware"/>
/// completes them on the first authenticated request that carries the pending invitation (Phase 2), and
/// <see cref="InviteCallbackCompletion"/> completes them on the provider callback itself so no follow-up
/// request — and no cookie round-trip — stands between the sign-in and the completed invitation.
/// </remarks>
interface IInviteCompletion
{
    /// <summary>
    /// Runs the invitation exchange for a request whose session was already established — the post-login
    /// middleware path.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="inviteToken">The re-validated invitation capability.</param>
    /// <returns>The outcome of the exchange.</returns>
    Task<InviteExchangeResult> ExchangeForRequest(HttpContext context, string inviteToken);

    /// <summary>
    /// Runs the invitation exchange for a freshly received provider ticket — the callback path, where the
    /// session is about to be established rather than already authenticated.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="inviteToken">The re-validated invitation capability.</param>
    /// <param name="principal">The freshly authenticated principal from the ticket.</param>
    /// <param name="properties">The round-tripped challenge properties from the ticket.</param>
    /// <returns>The outcome of the exchange.</returns>
    Task<InviteExchangeResult> ExchangeForTicket(HttpContext context, string inviteToken, ClaimsPrincipal principal, AuthenticationProperties properties);

    /// <summary>
    /// Resolves whether a successfully completed invitation should take the browser to the configured lobby.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="inviteToken">The completed invitation capability.</param>
    /// <param name="lobbyRedirectUrl">The lobby frontend URL, with the invitation id appended when configured.</param>
    /// <returns>
    /// <see langword="true"/> when the selected destination is Lobby and a lobby frontend is configured;
    /// otherwise <see langword="false"/>, meaning the browser continues toward its return URL.
    /// </returns>
    bool TryResolveLobbyRedirect(HttpContext context, string inviteToken, out string lobbyRedirectUrl);
}
