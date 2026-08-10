// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_binding_the_invite_to_the_invited_email;

/// <summary>
/// A GitHub account whose email is private supplies no address at all: <c>/user</c> returns a null email, so
/// no <c>email</c> claim is written and only <c>preferred_username</c> — the login name — is left. That is not
/// an address, and reporting it as a mismatch names a specific, wrong cause: the account and the address are
/// both the right ones. <em>No address available</em> and <em>a different person's address</em> are the two
/// cases a binding has to tell apart.
/// </summary>
public class and_the_provider_supplies_no_email_address : given.an_invite_exchange
{
    protected override string InviteEmailClaim => "email";

    void Establish()
    {
        GivenAuthenticatedUserWith(new Claim("preferred_username", "someuser"));
        GivenPendingInviteCookie(CreateSignedToken(claims: [new Claim("email", "someuser@example.com")]));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_forward_to_the_exchange_endpoint() => _exchangeCalled.ShouldBeFalse();
    [Fact] void should_not_continue_the_pipeline() => _nextCalled.ShouldBeFalse();
    [Fact] void should_serve_the_invitation_email_unavailable_page() =>
        _errorPageProvider.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.InvitationEmailUnavailable, StatusCodes.Status403Forbidden);
    [Fact] void should_not_accuse_the_account_of_being_the_wrong_one() =>
        _errorPageProvider.DidNotReceive().WriteErrorPageAsync(_context, WellKnownPageNames.InvitationEmailMismatch, Arg.Any<int>());
    [Fact] void should_delete_the_invite_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain(Cookies.InviteToken);
}
