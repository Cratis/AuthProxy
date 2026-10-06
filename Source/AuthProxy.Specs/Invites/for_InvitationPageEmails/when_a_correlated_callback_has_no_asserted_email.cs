// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationPageEmails;

public class when_a_correlated_callback_has_no_asserted_email : given.a_callback_invitation
{
    void Establish()
    {
        _asserted = null;
        GivenACallback();
    }

    Task Because() => CompleteCallback();

    [Fact] void should_answer_with_the_unavailable_page() => _page.ShouldEqual(WellKnownPageNames.InvitationEmailUnavailable);
    [Fact] void should_supply_the_invited_address() => _substitutions!["{{invitedEmail}}"].ShouldEqual(_invited);
    [Fact] void should_supply_an_empty_asserted_address() => _substitutions!["{{assertedEmail}}"].ShouldBeEmpty();
}
