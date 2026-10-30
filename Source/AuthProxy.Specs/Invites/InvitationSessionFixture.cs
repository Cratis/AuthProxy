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
    public static void GivenSessionEstablishedBeforeTheInvitation(HttpContext context) =>
        GivenSession(context, _ => { }, DateTimeOffset.UtcNow.AddDays(-7));

    /// <summary>
    /// Establishes a session issued after the invitation came into existence that carries no invitation
    /// binding — for example one the provider round-trip returned without AuthProxy's challenge properties.
    /// </summary>
    /// <param name="context">The context to establish the session on.</param>
    /// <remarks>
    /// The issue instant is deliberately later than the invitation's own: the session's age is not evidence
    /// of which invitation, if any, it answers, so it must be refused all the same.
    /// </remarks>
    public static void GivenSessionEstablishedAfterTheInvitationWithoutItsBinding(HttpContext context) =>
        GivenSession(context, _ => { }, DateTimeOffset.UtcNow.AddSeconds(5));

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
