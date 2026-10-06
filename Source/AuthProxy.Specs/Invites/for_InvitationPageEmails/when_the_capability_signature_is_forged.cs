// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationPageEmails;

public class when_the_capability_signature_is_forged : given.an_email_bound_invitation
{
    void Establish()
    {
        var (otherKey, _) = TokenFixture.GenerateKeyPair();
        _context.Request.Path = $"/invite/{CreateSignedToken(signingKey: otherKey, claims: [new Claim(InviteEmailClaim, _invited)])}";
    }

    Task Because() => _middleware.InvokeAsync(_context);

    [Fact] void should_refuse_the_capability() => _page.ShouldEqual(WellKnownPageNames.InvitationInvalid);
    [Fact] void should_disclose_no_addresses() => _substitutions.ShouldBeNull();
}
