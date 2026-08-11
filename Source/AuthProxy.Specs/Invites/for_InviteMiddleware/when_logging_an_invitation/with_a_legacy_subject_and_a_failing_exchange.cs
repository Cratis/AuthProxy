// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_logging_an_invitation;

/// <summary>
/// The status the exchange endpoint answered with is the whole diagnostic — it is bounded, and it is what an
/// operator acts on. The authenticated subject adds nothing to it.
/// </summary>
public class with_a_legacy_subject_and_a_failing_exchange : given.an_invite_exchange_with_recorded_logs
{
    protected override HttpStatusCode ExchangeStatusCode => HttpStatusCode.BadGateway;

    void Establish()
    {
        GivenLegacyAuthenticatedUserWith();
        GivenPendingInviteCookie(CreateSignedToken());
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_disclose_the_provider_subject() => _logger.Text.ShouldNotContain(SensitiveSubject);
    [Fact] void should_still_record_the_bounded_reason() => _logger.Text.ShouldContain("502");
}
