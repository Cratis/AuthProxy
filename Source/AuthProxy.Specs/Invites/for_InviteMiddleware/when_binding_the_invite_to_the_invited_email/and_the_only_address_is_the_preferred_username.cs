// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_binding_the_invite_to_the_invited_email;

/// <summary>
/// Some OIDC providers put the account's address in <c>preferred_username</c> — Entra's is the user principal
/// name. The binding still has to accept it: what disqualifies the claim is holding a username, not the claim
/// it arrived in. This is the control for
/// <see cref="and_the_provider_supplies_no_email_address"/>, which differs only in the shape of the value.
/// </summary>
public class and_the_only_address_is_the_preferred_username : given.an_invite_exchange
{
    protected override string InviteEmailClaim => "email";

    void Establish()
    {
        GivenAuthenticatedUserWith(new Claim("preferred_username", "invited@example.com"));
        GivenPendingInviteCookie(CreateSignedToken(claims: [new Claim("email", "invited@example.com")]));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_forward_to_the_exchange_endpoint() => _exchangeCalled.ShouldBeTrue();
    [Fact] void should_forward_the_address_as_the_authenticated_email() =>
        _exchangeRequestBody.ShouldContain("invited@example.com");
    [Fact] void should_not_serve_an_error_page() =>
        _errorPageProvider.DidNotReceive().WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>());
}
