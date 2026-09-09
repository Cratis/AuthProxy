// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_logging_an_attested_invitation;

/// <summary>
/// The session answered a different challenge than the one this invitation staged. A second stage, refused
/// for a second reason, proves the reason travels from wherever the guard sits rather than one stage having
/// been wired up by hand — and the challenge values themselves stay out of the log.
/// </summary>
public class with_a_challenge_binding_mismatch : given.an_attested_invite_completion
{
    protected override string SessionChallenge => "a-challenge-from-another-invitation";

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_issue_a_complete_attestation() => _attestationIssuer.Identity.ShouldBeNull();
    [Fact] void should_record_the_bounded_stage_reason() => _logger.Text.ShouldContain(nameof(InvitationCompletionFailureReason.ChallengeBindingMismatch));
    [Fact] void should_not_record_the_other_stages_reason() => _logger.Text.ShouldNotContain(nameof(InvitationCompletionFailureReason.EntryStateUnprotectFailed));
    [Fact] void should_not_disclose_the_capability() => _logger.Text.ShouldNotContain(_inviteToken);
    [Fact] void should_not_disclose_the_expected_challenge() => _logger.Text.ShouldNotContain(Challenge);
    [Fact] void should_not_disclose_the_presented_challenge() => _logger.Text.ShouldNotContain(SessionChallenge);
    [Fact] void should_not_disclose_the_invited_email() => _logger.Text.ShouldNotContain(Email);
}
