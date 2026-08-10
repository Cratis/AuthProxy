// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_logging_an_invitation;

/// <summary>
/// A legacy session's subject is the raw provider-supplied identifier for a person, and every provider that
/// has not opted into canonical identity is legacy. Refusing the exchange records why it was refused, never
/// who it was refused for.
/// </summary>
public class with_a_legacy_subject_and_an_email_mismatch : given.an_invite_exchange_with_recorded_logs
{
    protected override string InviteEmailClaim => "email";

    void Establish()
    {
        GivenLegacyAuthenticatedUserWith(new Claim("email", "someone-else@example.com"), new Claim("email_verified", "true"));
        GivenPendingInviteCookie(CreateSignedToken(claims: [new Claim("email", "invited@example.com")]));
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_disclose_the_provider_subject() => _logger.Text.ShouldNotContain(SensitiveSubject);
    [Fact] void should_still_record_the_bounded_reason() => _logger.Text.ShouldContain("does not match the invited email");
}
