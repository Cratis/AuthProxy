// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites.for_InviteMiddleware.given;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware;

/// <summary>
/// The identity provider supplied the invited address itself but no <c language="text">email_verified</c> claim at all. The
/// attested protocol never treats an absent verification claim as an unknown it can skip past - it is
/// evaluated as unverified, exactly like an explicit <see langword="false"/>, so this is answered with the
/// same actionable mismatch outcome and never with a silent success.
/// </summary>
public class when_completing_an_attested_invitation_with_a_missing_verification_claim : an_attested_invite_completion
{
    protected override IReadOnlyList<Claim> InvitationClaims => [new(InvitationAttestationClaims.Email, Email)];

    async Task Because()
    {
        var identity = (ClaimsIdentity)_context.User.Identity!;
        identity.RemoveClaim(identity.FindFirst("email_verified"));

        await _middleware.InvokeAsync(_context);
    }

    [Fact] void should_not_call_the_completion_endpoint() => _handler.Request.ShouldBeNull();
    [Fact] void should_not_issue_a_complete_attestation() => _attestationIssuer.Identity.ShouldBeNull();
    [Fact] void should_not_continue_the_pipeline() => _nextCalled.ShouldBeFalse();
    [Fact] void should_serve_the_email_mismatch_page() => _errorPageProvider.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.InvitationEmailMismatch, StatusCodes.Status403Forbidden);
}
