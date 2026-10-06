// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.ErrorPages.for_ErrorPageProvider;

public class when_invitation_addresses_are_substituted : given.an_invitation_page
{
    void Establish()
    {
        GivenTemplate("<html><head></head><body>{{invitedEmail}}|{{assertedEmail}}</body></html>");
        InvitationPageEmails.Remember(_context, new("{{assertedEmail}}@example.com", "<script>selected</script>@example.com"));
    }

    Task Because() => _provider.WriteErrorPageAsync(_context, WellKnownPageNames.InvitationEmailMismatch, StatusCodes.Status403Forbidden, InvitationPageEmails.ForRequest(_context, includeAssertedEmail: true));

    [Fact] void should_render_the_recipient_without_recursive_replacement() => Body().ShouldContain("&#123;&#123;assertedEmail&#125;&#125;@example.com");
    [Fact] void should_render_the_asserted_address_as_text() => Body().ShouldContain("&lt;script&gt;selected&lt;/script&gt;@example.com");
    [Fact] void should_not_render_a_script_element() => Body().ShouldNotContain("<script>");
}
