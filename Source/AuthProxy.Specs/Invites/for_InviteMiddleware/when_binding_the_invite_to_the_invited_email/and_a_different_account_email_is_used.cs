// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_binding_the_invite_to_the_invited_email;

public class and_a_different_account_email_is_used : given.an_invite_exchange
{
    void Establish()
    {
        // The account that logged in is not the one the invitation was issued for.
        GivenAuthenticatedUserWith(new Claim("email", "attacker@example.com"), new Claim("email_verified", "true"));
        GivenPendingInviteCookie(CreateSignedToken(claims: [new Claim("email", "invited@example.com")]));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_forward_to_the_exchange_endpoint() => _exchangeCalled.ShouldBeFalse();
    [Fact] void should_not_continue_the_pipeline() => _nextCalled.ShouldBeFalse();
    [Fact] void should_serve_the_invitation_email_mismatch_page() =>
        _errorPageProvider.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.InvitationEmailMismatch, StatusCodes.Status403Forbidden);
    [Fact] void should_delete_the_invite_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain(Cookies.InviteToken);
}
