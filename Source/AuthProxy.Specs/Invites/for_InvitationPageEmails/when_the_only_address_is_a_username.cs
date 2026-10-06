// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationPageEmails;

public class when_the_only_address_is_a_username : given.an_email_bound_invitation
{
    protected override IReadOnlyList<Claim> ProviderClaims => [new("preferred_username", "selected@example.com")];

    void Establish() => GivenAnExchange();

    Task Because() => _middleware.InvokeAsync(_context);

    [Fact] void should_preserve_the_existing_binding_outcome() => _page.ShouldEqual(WellKnownPageNames.InvitationEmailMismatch);
    [Fact] void should_not_infer_an_asserted_address_for_display() => _substitutions!["{{assertedEmail}}"].ShouldBeEmpty();
}
