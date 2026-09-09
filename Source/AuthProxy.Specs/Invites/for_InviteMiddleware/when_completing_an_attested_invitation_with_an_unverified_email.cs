// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites.for_InviteMiddleware.given;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware;

/// <summary>
/// The identity provider supplied the invited address itself, but explicitly flagged it as unverified. An
/// unverified claim of the right address is not trusted evidence, and is answered with the same actionable
/// mismatch outcome as a verified but different address - never a generic invalid-link denial.
/// </summary>
public class when_completing_an_attested_invitation_with_an_unverified_email : an_attested_invite_completion
{
    protected override IReadOnlyList<Claim> InvitationClaims => [new(InvitationAttestationClaims.Email, Email)];

    async Task Because()
    {
        var identity = (ClaimsIdentity)_context.User.Identity!;
        var verifiedClaim = identity.FindFirst("email_verified")!;
        identity.RemoveClaim(verifiedClaim);
        identity.AddClaim(new Claim("email_verified", bool.FalseString.ToLowerInvariant()));

        await _middleware.InvokeAsync(_context);
    }

    [Fact] void should_not_call_the_completion_endpoint() => _handler.Request.ShouldBeNull();
    [Fact] void should_not_issue_a_complete_attestation() => _attestationIssuer.Identity.ShouldBeNull();
    [Fact] void should_not_continue_the_pipeline() => _nextCalled.ShouldBeFalse();
    [Fact] void should_serve_the_email_mismatch_page() => _errorPageProvider.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.InvitationEmailMismatch, StatusCodes.Status403Forbidden);
}
