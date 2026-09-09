// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_the_configuration_reloads_during_completion;

/// <summary>
/// The invited-email claim type is renamed while the completion is awaiting the session, and the account
/// answering the challenge is somebody else's. A completion stage that re-read the claim type at this point
/// would find the capability carrying no invited address, read that as an invitation bound to nobody, and
/// hand a signed attestation for the wrong person to the exchange endpoint.
/// </summary>
public class and_the_email_claim_is_renamed_for_another_account : given.an_attested_invite_completion
{
    protected override string? ReloadedEmailClaimDuringSession => "renamed_invited_email";

    async Task Because()
    {
        var identity = (ClaimsIdentity)_context.User.Identity!;
        identity.RemoveClaim(identity.FindFirst("email"));
        identity.AddClaim(new Claim("email", "someone-else@example.com"));

        await _middleware.InvokeAsync(_context);
    }

    [Fact] void should_not_issue_a_complete_attestation() => _attestationIssuer.Identity.ShouldBeNull();
    [Fact] void should_not_call_the_completion_endpoint() => _handler.Request.ShouldBeNull();
    [Fact] void should_not_continue_the_pipeline() => _nextCalled.ShouldBeFalse();
    [Fact] void should_serve_the_email_mismatch_page() => _errorPageProvider.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.InvitationEmailMismatch, StatusCodes.Status403Forbidden);
}
