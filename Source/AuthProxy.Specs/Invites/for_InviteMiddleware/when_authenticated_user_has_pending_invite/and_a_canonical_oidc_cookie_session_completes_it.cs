// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_authenticated_user_has_pending_invite;

public class and_a_canonical_oidc_cookie_session_completes_it : given.a_canonical_invite_exchange
{
    protected override void ConfigureAuthentication(C.AuthProxy configuration) => configuration.Authentication = CanonicalOidcFixture.Configuration();

    void Establish()
    {
        GivenPendingInviteCookie(CreateSignedToken());
        _context.User = CanonicalOidcFixture.Principal();
        CanonicalOidcFixture.AuthenticateCookie(_context, _context.User);
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_exchange_the_invitation() => _exchangeCalled.ShouldBeTrue();
    [Fact] void should_post_the_canonical_subject() => _exchangeRequestBody.ShouldContain("\"subject\":\"configured-subject\"");
    [Fact] void should_post_the_provider_key() => _exchangeRequestBody.ShouldContain("\"providerKey\":\"workforce\"");
}
