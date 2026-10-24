// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationPageEmails;

public class when_substituting_an_address_with_disallowed_characters : Specification
{
    string[] _addresses;
    IReadOnlyDictionary<string, string>[] _substitutions;

    void Establish() => _addresses = [
        .. new[] { "<", ">", "\"", "'", " ", "\t", "\r", "\n", "\0", "\u001f", "\u007f", "%", "=", "`", "\\", ":", "/", "(", ")", "{", "}", "é" }.Select(character => $"person{character}name@example.com"),
        "person onmouseover=alert(1)@example.com",
        "javascript:alert(1)@example.com",
    ];

    void Because() => _substitutions = _addresses.Select(address =>
    {
        var context = new DefaultHttpContext();
        InvitationPageEmails.Remember(context, new(address, address));
        return InvitationPageEmails.ForRequest(context, includeAssertedEmail: true)!;
    }).ToArray();

    [Fact] void should_blank_the_invited_address() => _substitutions.ShouldEachConformTo(values => values["{{invitedEmail}}"].Length == 0);
    [Fact] void should_blank_the_asserted_address() => _substitutions.ShouldEachConformTo(values => values["{{assertedEmail}}"].Length == 0);
}
