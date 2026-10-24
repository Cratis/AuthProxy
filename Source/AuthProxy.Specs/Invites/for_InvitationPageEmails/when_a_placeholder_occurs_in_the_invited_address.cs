// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationPageEmails;

public class when_a_placeholder_occurs_in_the_invited_address : given.an_email_bound_invitation
{
    void Establish()
    {
        _invited = "{{assertedEmail}}@example.com";
        GivenAnExchange();
    }

    Task Because() => _middleware.InvokeAsync(_context);

    [Fact] void should_blank_the_address_containing_a_placeholder() => _substitutions!["{{invitedEmail}}"].ShouldBeEmpty();
}
