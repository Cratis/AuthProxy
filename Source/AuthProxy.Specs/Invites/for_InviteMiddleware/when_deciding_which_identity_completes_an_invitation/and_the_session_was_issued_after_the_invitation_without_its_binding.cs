// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_deciding_which_identity_completes_an_invitation;

/// <summary>
/// A session issued after the invitation came into existence is not evidence that the person authenticated for
/// that invitation. Without the invitation's own challenge binding nothing is exchanged, and the invitation
/// stays pending so the person can still answer it with the provider they choose.
/// </summary>
public class and_the_session_was_issued_after_the_invitation_without_its_binding : given.an_invite_exchange
{
    void Establish()
    {
        GivenAuthenticatedUserWith();
        var invitationIssuedAt = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds().ToString();
        GivenPendingInviteCookieOnASessionWithoutTheInvitationBinding(
            CreateSignedToken(claims: [new Claim("iat", invitationIssuedAt)]));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_forward_to_the_exchange_endpoint() => _exchangeCalled.ShouldBeFalse();
    [Fact] void should_leave_the_invitation_pending() => _context.Response.Headers.SetCookie.ToString().ShouldNotContain(Cookies.InviteToken);
    [Fact] void should_continue_the_pipeline() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_redirect() => _context.Response.Headers.Location.ToString().ShouldBeEmpty();
    [Fact]
    void should_not_serve_an_error_page() =>
        _errorPageProvider.DidNotReceive().WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>(), Arg.Any<IReadOnlyDictionary<string, string>>());
}
