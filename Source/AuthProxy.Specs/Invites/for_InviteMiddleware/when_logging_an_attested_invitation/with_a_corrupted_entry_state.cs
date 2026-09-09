// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_logging_an_attested_invitation;

/// <summary>
/// The protected invitation-entry state the browser presents does not unprotect. The whole point of the
/// bounded reason is that an operator can tell this stage apart from every other refusal, so the stage is
/// named in the log — and nothing else about the request is.
/// </summary>
public class with_a_corrupted_entry_state : given.an_attested_invite_completion
{
    async Task Because()
    {
        _context.Request.Headers.Cookie = $"{Cookies.InviteToken}={_inviteToken}; {Cookies.InvitationEntryState}=corrupted-not-a-real-protected-payload";

        await _middleware.InvokeAsync(_context);
    }

    [Fact] void should_not_issue_a_complete_attestation() => _attestationIssuer.Identity.ShouldBeNull();
    [Fact] void should_record_the_bounded_stage_reason() => _logger.Text.ShouldContain(nameof(InvitationCompletionFailureReason.EntryStateUnprotectFailed));
    [Fact] void should_not_disclose_the_capability() => _logger.Text.ShouldNotContain(_inviteToken);
    [Fact] void should_not_disclose_the_invited_email() => _logger.Text.ShouldNotContain(Email);
    [Fact] void should_not_disclose_the_invitation_transaction() => _logger.Text.ShouldNotContain(Transaction);
    [Fact] void should_not_disclose_the_invitation_challenge() => _logger.Text.ShouldNotContain(Challenge);
    [Fact] void should_not_disclose_the_provider_subject() => _logger.Text.ShouldNotContain("provider-subject");
}
