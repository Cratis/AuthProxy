// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites.for_InviteMiddleware.given;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_authenticated_user_has_pending_invite;

public class and_canonical_identity_is_configured : a_canonical_invite_exchange
{
    protected override void ConfigureAuthentication(C.AuthProxy configuration) =>
        configuration.Authentication = new C.Authentication
        {
            OAuthProviders =
            [
                new C.OAuthProvider
                {
                    Name = "GitHub",
                    CanonicalIdentity = new C.CanonicalIdentity
                    {
                        ProviderKey = "workforce",
                        SubjectClaimType = "oid",
                        Issuer = "https://identity.example.com/"
                    }
                }
            ]
        };

    void Establish()
    {
        GivenPendingInviteCookie(CreateSignedToken());
        GivenAuthenticatedUserWith(
            new Claim("oid", "configured-subject"),
            new Claim("sub", "old-sub"),
            new Claim("name", "Cosmetic Name"));
        _context.User = new ClaimsPrincipal(new ClaimsIdentity(_context.User.Claims, "github"));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_exchange_the_invite() => _exchangeCalled.ShouldBeTrue();
    [Fact] void should_post_the_configured_subject() => _exchangeRequestBody.ShouldContain("\"subject\":\"configured-subject\"");
    [Fact] void should_post_the_provider_key() => _exchangeRequestBody.ShouldContain("\"providerKey\":\"workforce\"");
    [Fact] void should_post_the_normalized_issuer() => _exchangeRequestBody.ShouldContain("\"issuer\":\"https://identity.example.com\"");
    [Fact] void should_not_post_an_old_fallback_subject() => _exchangeRequestBody.ShouldNotContain("old-sub");
}
