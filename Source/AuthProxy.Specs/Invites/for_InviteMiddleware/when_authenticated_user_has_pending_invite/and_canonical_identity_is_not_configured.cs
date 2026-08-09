// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites.for_InviteMiddleware.given;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_authenticated_user_has_pending_invite;

public class and_canonical_identity_is_not_configured : an_invite_exchange
{
    void Establish()
    {
        GivenPendingInviteCookie(CreateSignedToken());
        GivenAuthenticatedUserWith(new Claim("oid", "different-object-id"));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_preserve_the_legacy_sub_first_selection() => _exchangeRequestBody.ShouldContain("\"subject\":\"user-123\"");
    [Fact] void should_not_add_a_canonical_provider_key() => _exchangeRequestBody.ShouldNotContain("providerKey");
}
