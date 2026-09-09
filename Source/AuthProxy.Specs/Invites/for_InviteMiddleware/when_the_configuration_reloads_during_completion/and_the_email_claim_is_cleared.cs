// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_the_configuration_reloads_during_completion;

/// <summary>
/// The invited-email claim type is blanked while the completion is awaiting the session, and the identity
/// provider supplies no address at all. A completion stage that re-read the configuration would treat the
/// blank claim type as an invitation bound to nobody and attest an identity with no verified address on it.
/// </summary>
public class and_the_email_claim_is_cleared : given.an_attested_invite_completion
{
    protected override bool IncludeVerifiedEmailClaims => false;
    protected override string? ReloadedEmailClaimDuringSession => string.Empty;

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_issue_a_complete_attestation() => _attestationIssuer.Identity.ShouldBeNull();
    [Fact] void should_not_call_the_completion_endpoint() => _handler.Request.ShouldBeNull();
    [Fact] void should_not_continue_the_pipeline() => _nextCalled.ShouldBeFalse();
    [Fact] void should_serve_the_email_unavailable_page() => _errorPageProvider.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.InvitationEmailUnavailable, StatusCodes.Status403Forbidden);
}
