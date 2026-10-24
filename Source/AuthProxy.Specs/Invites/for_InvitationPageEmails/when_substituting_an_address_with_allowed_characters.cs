// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationPageEmails;

public class when_substituting_an_address_with_allowed_characters : Specification
{
    const string Address = "First.Last_123+tag-name@Sub-Domain.example.com";
    IReadOnlyDictionary<string, string> _substitutions;

    void Because()
    {
        var context = new DefaultHttpContext();
        InvitationPageEmails.Remember(context, new(Address, Address));
        _substitutions = InvitationPageEmails.ForRequest(context, includeAssertedEmail: true)!;
    }

    [Fact] void should_supply_the_invited_address() => _substitutions["{{invitedEmail}}"].ShouldEqual(Address);
    [Fact] void should_supply_the_asserted_address() => _substitutions["{{assertedEmail}}"].ShouldEqual(Address);
}
