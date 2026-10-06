// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.ErrorPages.for_ErrorPageProvider;

public class when_an_invitation_page_omits_the_email_tokens : given.an_invitation_page
{
    void Establish()
    {
        GivenTemplate("<html><head></head><body>Existing invitation wording</body></html>");
        InvitationPageEmails.Remember(_context, new("invited@example.com", "selected@example.com"));
    }

    Task Because() => _provider.WriteErrorPageAsync(_context, WellKnownPageNames.InvitationEmailMismatch, StatusCodes.Status403Forbidden, InvitationPageEmails.ForRequest(_context, includeAssertedEmail: true));

    [Fact] void should_preserve_the_existing_page_content() => Body().ShouldEqual("<html><head><base href=\"/_pages/\"></head><body>Existing invitation wording</body></html>");
}
