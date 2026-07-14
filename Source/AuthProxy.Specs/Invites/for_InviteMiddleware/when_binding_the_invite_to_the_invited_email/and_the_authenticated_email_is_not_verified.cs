// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_binding_the_invite_to_the_invited_email;

public class and_the_authenticated_email_is_not_verified : given.an_invite_exchange
{
    const string InvitedEmail = "invited@example.com";

    void Establish()
    {
        // The email matches, but the provider explicitly reports it as unverified.
        GivenAuthenticatedUserWith(new Claim("email", InvitedEmail), new Claim("email_verified", "false"));
        GivenPendingInviteCookie(CreateSignedToken(claims: [new Claim("email", InvitedEmail)]));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_forward_to_the_exchange_endpoint() => _exchangeCalled.ShouldBeFalse();
    [Fact] void should_not_continue_the_pipeline() => _nextCalled.ShouldBeFalse();
    [Fact] void should_serve_the_invitation_email_mismatch_page() =>
        _errorPageProvider.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.InvitationEmailMismatch, StatusCodes.Status403Forbidden);
}
