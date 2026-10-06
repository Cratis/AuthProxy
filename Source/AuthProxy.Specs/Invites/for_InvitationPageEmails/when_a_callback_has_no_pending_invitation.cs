// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationPageEmails;

public class when_a_callback_has_no_pending_invitation : given.a_callback_invitation
{
    void Establish()
    {
        GivenACallback();
        _context.Request.Headers.Cookie = string.Empty;
    }

    Task Because() => CompleteCallback();

    [Fact] void should_leave_the_non_invitation_callback_alone() => _result.ShouldEqual(InviteCallbackCompletionResult.NotCompleted);
    [Fact] void should_disclose_no_addresses() => _substitutions.ShouldBeNull();
    [Fact] void should_not_write_an_invitation_page() => _page.ShouldBeEmpty();
}
