// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationPageEmails;

public class when_a_static_page_is_requested : given.an_email_bound_invitation
{
    void Establish()
    {
        _context.Request.Path = "/.cratis/pages/invitation-email-mismatch.html";
        GivenAuthenticatedUserWith([.. ProviderClaims]);
    }

    Task Because() => _middleware.InvokeAsync(_context);

    [Fact] void should_continue_without_invitation_handling() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_supply_invitation_substitutions() => _substitutions.ShouldBeNull();
    [Fact] void should_not_write_an_invitation_page() => _page.ShouldBeEmpty();
}
