// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_logging_an_invitation;

/// <summary>
/// The success line is written at information level on every legacy-mode exchange, so it is the highest-volume
/// place a subject could have leaked from — an ordinary, fully working invitation would have published one.
/// </summary>
public class with_a_legacy_subject_and_a_successful_exchange : given.an_invite_exchange_with_recorded_logs
{
    void Establish()
    {
        GivenLegacyAuthenticatedUserWith();
        GivenPendingInviteCookie(CreateSignedToken());
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_disclose_the_provider_subject() => _logger.Text.ShouldNotContain(SensitiveSubject);
    [Fact] void should_still_record_the_bounded_reason() => _logger.Text.ShouldContain("Invite exchanged successfully");
}
