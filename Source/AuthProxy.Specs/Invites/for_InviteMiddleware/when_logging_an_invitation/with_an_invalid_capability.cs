// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_logging_an_invitation;

/// <summary>
/// An invitation arrives as <c>/invite/{capability}</c>, so on a Phase-1 invitation request the request path
/// <em>is</em> a live bearer capability. Refusing it must not be the thing that writes it to every log sink.
/// </summary>
public class with_an_invalid_capability : given.an_invite_exchange_with_recorded_logs
{
    void Establish() => GivenInvitationRequestFor(SensitiveCapability);

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_disclose_the_capability() => _logger.Text.ShouldNotContain(SensitiveCapability);
    [Fact] void should_still_record_the_bounded_reason() => _logger.Text.ShouldContain("Invite token validation failed");
}
