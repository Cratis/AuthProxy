// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_binding_the_invite_to_the_invited_email;

public class and_the_verified_email_is_forwarded_to_the_exchange : given.an_invite_exchange
{
    const string AuthenticatedEmail = "invited@example.com";

    void Establish()
    {
        // No EmailClaim override: enforcement is off (the default). The verified email is still forwarded.
        GivenAuthenticatedUserWith(new Claim("email", AuthenticatedEmail), new Claim("email_verified", "true"));
        GivenPendingInviteCookie(CreateSignedToken());
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_include_the_email_in_the_exchange_body() => _exchangeRequestBody.ShouldContain(AuthenticatedEmail);
    [Fact] void should_include_the_email_field_in_the_exchange_body() => _exchangeRequestBody.ShouldContain("email");
}
