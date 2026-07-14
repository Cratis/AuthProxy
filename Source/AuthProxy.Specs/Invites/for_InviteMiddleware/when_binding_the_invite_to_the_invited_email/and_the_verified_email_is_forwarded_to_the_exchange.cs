// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_binding_the_invite_to_the_invited_email;

public class and_the_verified_email_is_forwarded_to_the_exchange : given.an_invite_exchange
{
    const string InvitedEmail = "invited@example.com";

    void Establish()
    {
        GivenAuthenticatedUserWith(new Claim("email", InvitedEmail), new Claim("email_verified", "true"));
        GivenPendingInviteCookie(CreateSignedToken(claims: [new Claim("email", InvitedEmail)]));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_include_the_email_in_the_exchange_body() => _exchangeRequestBody.ShouldContain(InvitedEmail);
    [Fact] void should_include_the_email_field_in_the_exchange_body() => _exchangeRequestBody.ShouldContain("email");
}
