// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_logging_an_invitation;

/// <summary>
/// A call that never produces a response is reported by the endpoint it could not reach — a configured URL,
/// not caller-supplied content — and carries neither the capability nor the authenticated subject.
/// </summary>
public class with_an_exchange_call_that_throws : given.an_invite_exchange_with_recorded_logs
{
    protected override bool ExchangeCallThrows => true;

    string _capability;

    void Establish()
    {
        _capability = CreateSignedToken();
        GivenLegacyAuthenticatedUserWith();
        GivenPendingInviteCookie(_capability);
        GivenInvitationRequestFor(_capability);
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_disclose_the_capability() => _logger.Text.ShouldNotContain(_capability);
    [Fact] void should_not_disclose_the_provider_subject() => _logger.Text.ShouldNotContain(SensitiveSubject);
    [Fact] void should_still_record_the_bounded_reason() => _logger.Text.ShouldContain(ExchangeUrl);
}
