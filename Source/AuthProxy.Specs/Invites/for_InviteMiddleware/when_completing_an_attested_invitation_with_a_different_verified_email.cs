// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites.for_InviteMiddleware.given;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware;

/// <summary>
/// The identity provider supplied a verified email, but it belongs to a different account than the one the
/// invitation was issued for. This is a specific, actionable outcome distinct from
/// <see cref="when_completing_an_attested_invitation_without_verified_email"/> - the account and address are
/// both real, they are just the wrong ones - and must not be collapsed into a generic invalid-link denial.
/// </summary>
public class when_completing_an_attested_invitation_with_a_different_verified_email : an_attested_invite_completion
{
    protected override IReadOnlyList<Claim> InvitationClaims => [new(InvitationAttestationClaims.Email, Email)];

    async Task Because()
    {
        var identity = (ClaimsIdentity)_context.User.Identity!;
        var emailClaim = identity.FindFirst("email")!;
        identity.RemoveClaim(emailClaim);
        identity.AddClaim(new Claim("email", "someone-else@example.com"));

        await _middleware.InvokeAsync(_context);
    }

    [Fact] void should_not_call_the_completion_endpoint() => _handler.Request.ShouldBeNull();
    [Fact] void should_not_issue_a_complete_attestation() => _attestationIssuer.Identity.ShouldBeNull();
    [Fact] void should_not_continue_the_pipeline() => _nextCalled.ShouldBeFalse();
    [Fact] void should_serve_the_email_mismatch_page() => _errorPageProvider.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.InvitationEmailMismatch, StatusCodes.Status403Forbidden);
    [Fact] void should_not_serve_the_email_unavailable_page() => _errorPageProvider.DidNotReceive().WriteErrorPageAsync(_context, WellKnownPageNames.InvitationEmailUnavailable, Arg.Any<int>());
}
