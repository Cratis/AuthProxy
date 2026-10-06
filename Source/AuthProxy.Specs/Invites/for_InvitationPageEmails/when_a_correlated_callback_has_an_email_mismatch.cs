// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationPageEmails;

public class when_a_correlated_callback_has_an_email_mismatch : given.a_callback_invitation
{
    void Establish()
    {
        _invited = "<script>invite</script>@example.com";
        _asserted = "<b>selected</b>@example.com";
        GivenACallback();
    }

    Task Because() => CompleteCallback();

    [Fact] void should_handle_the_callback_response() => _result.ShouldEqual(InviteCallbackCompletionResult.ResponseHandled);
    [Fact] void should_answer_with_the_mismatch_page() => _page.ShouldEqual(WellKnownPageNames.InvitationEmailMismatch);
    [Fact] void should_encode_the_validated_recipient() => _substitutions!["{{invitedEmail}}"].ShouldEqual("&lt;script&gt;invite&lt;/script&gt;@example.com");
    [Fact] void should_encode_the_provider_address() => _substitutions!["{{assertedEmail}}"].ShouldEqual("&lt;b&gt;selected&lt;/b&gt;@example.com");
}
