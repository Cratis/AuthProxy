// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationPageEmails;

public class when_more_than_one_email_was_asserted : given.an_email_bound_invitation
{
    protected override IReadOnlyList<Claim> ProviderClaims => [new("email", "first@example.com"), new("email", "second@example.com"), new("email_verified", "true")];

    void Establish() => GivenAnExchange();

    Task Because() => _middleware.InvokeAsync(_context);

    [Fact] void should_preserve_the_existing_binding_outcome() => _page.ShouldEqual(WellKnownPageNames.InvitationEmailMismatch);
    [Fact] void should_not_choose_an_address_to_display() => _substitutions!["{{assertedEmail}}"].ShouldBeEmpty();
}
