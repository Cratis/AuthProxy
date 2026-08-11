// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_logging_an_invitation;

/// <summary>
/// A provider that supplied no address at all is a different refusal from a provider that supplied somebody
/// else's, and both are reported without naming the authenticated subject.
/// </summary>
public class with_a_legacy_subject_and_an_unavailable_email : given.an_invite_exchange_with_recorded_logs
{
    protected override string InviteEmailClaim => "email";

    void Establish()
    {
        GivenLegacyAuthenticatedUserWith(new Claim("preferred_username", "someuser"));
        GivenPendingInviteCookie(CreateSignedToken(claims: [new Claim("email", "invited@example.com")]));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_disclose_the_provider_subject() => _logger.Text.ShouldNotContain(SensitiveSubject);
    [Fact] void should_still_record_the_bounded_reason() => _logger.Text.ShouldContain("supplied no email address");
}
