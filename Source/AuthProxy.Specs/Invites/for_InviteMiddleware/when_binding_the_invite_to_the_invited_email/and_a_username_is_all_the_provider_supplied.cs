// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_binding_the_invite_to_the_invited_email;

/// <summary>
/// With enforcement off the exchange still runs, and the account's email is forwarded so the backend can apply
/// its own defense-in-depth check. A login name must not travel in that field: the backend has no way to tell it
/// from an address, and a backstop that fails closed on an empty value would be handed a value that looks real.
/// </summary>
public class and_a_username_is_all_the_provider_supplied : given.an_invite_exchange
{
    const string Username = "someuser";

    void Establish()
    {
        // No EmailClaim override: enforcement is off, so the exchange is reached.
        GivenAuthenticatedUserWith(new Claim("preferred_username", Username));
        GivenPendingInviteCookie(CreateSignedToken());
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_still_forward_to_the_exchange_endpoint() => _exchangeCalled.ShouldBeTrue();
    [Fact] void should_not_forward_the_username_as_the_account_email() => _exchangeRequestBody.ShouldNotContain(Username);
    [Fact] void should_forward_no_email_at_all() => _exchangeRequestBody.ShouldContain("\"email\":\"\"");
}
