// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_logging_an_invitation;

/// <summary>
/// The Phase-2 re-validation runs on a request that came back to the invitation URL, so the capability is on
/// the path there too — and this time it is also in the pending-invitation cookie. Refusing to forward it
/// must not disclose it.
/// </summary>
public class with_a_capability_rejected_at_the_phase_two_forward : given.an_invite_exchange_with_recorded_logs
{
    void Establish()
    {
        GivenAuthenticatedUserWith();
        GivenPendingInviteCookie(SensitiveCapability);
        GivenInvitationRequestFor(SensitiveCapability);
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_disclose_the_capability() => _logger.Text.ShouldNotContain(SensitiveCapability);
    [Fact] void should_still_record_the_bounded_reason() => _logger.Text.ShouldContain(nameof(InviteTokenValidationResult.Invalid));
}
