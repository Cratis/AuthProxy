// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_logging_an_invitation;

/// <summary>
/// An expired capability is still a signed bearer token, and expiry is a claim inside it rather than
/// something a log sink can be trusted to honor. The whole token stays out of the log; only the outcome that
/// made the request fail goes in.
/// </summary>
public class with_an_expired_capability : given.an_invite_exchange_with_recorded_logs
{
    string _capability;

    void Establish()
    {
        _capability = CreateSignedToken(
            expires: DateTime.UtcNow.AddMinutes(-10),
            notBefore: DateTime.UtcNow.AddMinutes(-20));
        GivenInvitationRequestFor(_capability);
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_disclose_the_capability() => _logger.Text.ShouldNotContain(_capability);
    [Fact] void should_still_record_the_bounded_reason() => _logger.Text.ShouldContain("Invite token validation failed");
    [Fact] void should_name_the_expiry_as_the_outcome() => _logger.Text.ShouldContain(nameof(InviteTokenValidationResult.Expired));
}
