// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Establishes, on a specification's HTTP context, the authentication result the request is running as.
/// </summary>
/// <remarks>
/// That result is the evidence <see cref="InviteMiddleware"/> reads to tell a session established by an
/// invitation's own challenge apart from one the browser was already carrying, so a specification that
/// exercises the post-login exchange has to say which of the two it is modeling. In a running proxy the
/// authentication middleware publishes it after the provider handshake signs a ticket in.
/// </remarks>
static class InvitationSessionFixture
{
    /// <summary>
    /// Establishes a session that answered the provider challenge started for one exact invitation.
    /// </summary>
    /// <param name="context">The context to establish the session on.</param>
    /// <param name="invitationToken">The invitation capability the challenge was started for.</param>
    public static void GivenSessionEstablishedByTheInvitation(HttpContext context, string invitationToken) =>
        GivenSession(context, properties => InvitationAuthenticationState.BindCapability(properties, invitationToken), DateTimeOffset.UtcNow.AddSeconds(5));

    /// <summary>
    /// Establishes a session that predates the invitation — signed in earlier, for something else, and
    /// therefore carrying no invitation binding at all.
    /// </summary>
    /// <param name="context">The context to establish the session on.</param>
    /// <remarks>
    /// The issue instant is part of the fact being modeled: the completion gate falls back to comparing it
    /// against the invitation's own issue instant when the capability binding is absent, so a session from
    /// before the invitation existed must genuinely carry an older one.
    /// </remarks>
    public static void GivenSessionEstablishedBeforeTheInvitation(HttpContext context) =>
        GivenSession(context, _ => { }, DateTimeOffset.UtcNow.AddDays(-7));

    static void GivenSession(HttpContext context, Action<AuthenticationProperties> bind, DateTimeOffset issuedUtc)
    {
        var properties = new AuthenticationProperties { IssuedUtc = issuedUtc };
        bind(properties);

        var scheme = context.User.Identity?.AuthenticationType ?? "test-scheme";
        context.Features.Set<IAuthenticateResultFeature>(new EstablishedSession(
            AuthenticateResult.Success(new AuthenticationTicket(context.User, properties, scheme))));
    }

    sealed class EstablishedSession(AuthenticateResult result) : IAuthenticateResultFeature
    {
        public AuthenticateResult? AuthenticateResult { get; set; } = result;
    }
}
