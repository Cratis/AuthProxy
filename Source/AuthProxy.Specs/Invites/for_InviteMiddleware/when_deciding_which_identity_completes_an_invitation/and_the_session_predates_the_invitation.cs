// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_deciding_which_identity_completes_an_invitation;

/// <summary>
/// The account the browser was already signed in with is not the account the person chose for the
/// invitation, and an invitation binds an organization to an identity permanently. A pre-existing session
/// therefore completes nothing — and, because the person has not chosen yet, the invitation is left pending
/// rather than consumed or refused.
/// </summary>
public class and_the_session_predates_the_invitation : given.an_invite_exchange
{
    void Establish()
    {
        GivenAuthenticatedUserWith();
        GivenPendingInviteCookieOnAPreExistingSession(CreateSignedToken());
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_forward_to_the_exchange_endpoint() => _exchangeCalled.ShouldBeFalse();
    [Fact] void should_leave_the_invitation_pending() => _context.Response.Headers.SetCookie.ToString().ShouldNotContain(Cookies.InviteToken);
    [Fact] void should_continue_the_pipeline() => _nextCalled.ShouldBeTrue();
    [Fact]
    void should_not_serve_an_error_page() =>
        _errorPageProvider.DidNotReceive().WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>());
}
