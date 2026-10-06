// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationPageEmails;

public class when_a_mismatched_account_supplies_markup : given.an_email_bound_invitation
{
    void Establish()
    {
        _invited = "<script>invite</script>@example.com";
        _asserted = "<img src=x onerror=alert(1)>@example.com";
        GivenAnExchange();
    }

    Task Because() => _middleware.InvokeAsync(_context);

    [Fact] void should_answer_with_the_mismatch_page() => _page.ShouldEqual(WellKnownPageNames.InvitationEmailMismatch);
    [Fact] void should_encode_the_validated_invited_address() => _substitutions!["{{invitedEmail}}"].ShouldEqual("&lt;script&gt;invite&lt;/script&gt;@example.com");
    [Fact] void should_encode_the_single_asserted_address() => _substitutions!["{{assertedEmail}}"].ShouldEqual("&lt;img src=x onerror=alert(1)&gt;@example.com");
    [Fact] void should_not_exchange_the_invitation() => _exchangeCalled.ShouldBeFalse();
}
