// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_deciding_which_identity_completes_an_invitation;

/// <summary>
/// The whole point of the flow: the caller went through the invitation's own provider challenge, came back,
/// and the invitation completes with the identity they authenticated with — in one request, with no second
/// trip past the provider.
/// </summary>
public class and_the_session_answered_the_invitations_challenge : given.an_invite_exchange
{
    void Establish()
    {
        GivenAuthenticatedUserWith();
        GivenPendingInviteCookie(CreateSignedToken());
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_forward_to_the_exchange_endpoint() => _exchangeCalled.ShouldBeTrue();
    [Fact] void should_continue_the_pipeline() => _nextCalled.ShouldBeTrue();
    [Fact] void should_clear_the_pending_invitation() => _context.Response.Headers.SetCookie.ToString().ShouldContain(Cookies.InviteToken);
    [Fact]
    void should_not_serve_an_error_page() =>
        _errorPageProvider.DidNotReceive().WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>());
}
