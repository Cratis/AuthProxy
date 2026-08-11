// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_deciding_which_identity_completes_an_invitation;

/// <summary>
/// Which identity may complete an invitation is a question about a capability that validates, so the
/// capability is still re-validated first and a forged one is still answered with the invalid page and
/// cleared from the browser. Deciding the identity question first would turn a forged capability into a
/// silently pending one.
/// </summary>
public class and_a_pre_existing_session_carries_a_forged_capability : given.an_invite_exchange
{
    void Establish()
    {
        GivenAuthenticatedUserWith();
        GivenPendingInviteCookieOnAPreExistingSession(
            CreateSignedToken(signingKey: TokenFixture.GenerateKeyPair().PrivateKey));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_forward_to_the_exchange_endpoint() => _exchangeCalled.ShouldBeFalse();
    [Fact] void should_not_continue_the_pipeline() => _nextCalled.ShouldBeFalse();
    [Fact] void should_clear_the_pending_invitation() => _context.Response.Headers.SetCookie.ToString().ShouldContain(Cookies.InviteToken);
    [Fact]
    void should_serve_the_invitation_invalid_page() =>
        _errorPageProvider.Received(1).WriteErrorPageAsync(
            _context,
            WellKnownPageNames.InvitationInvalid,
            StatusCodes.Status401Unauthorized);
}
