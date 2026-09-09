// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites.for_InviteMiddleware.given;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware;

/// <summary>
/// The identity provider supplied two conflicting <c language="text">email</c> claims. A duplicated claim is not a single,
/// trustworthy address - the attested protocol requires exactly one - so this is evaluated exactly like no
/// address at all: the dedicated unavailable-address outcome, never a value picked from the ambiguous pair.
/// </summary>
public class when_completing_an_attested_invitation_with_a_duplicate_email_claim : an_attested_invite_completion
{
    protected override IReadOnlyList<Claim> InvitationClaims => [new(InvitationAttestationClaims.Email, Email)];

    async Task Because()
    {
        var identity = (ClaimsIdentity)_context.User.Identity!;
        identity.AddClaim(new Claim("email", "someone-else@example.com"));

        await _middleware.InvokeAsync(_context);
    }

    [Fact] void should_not_call_the_completion_endpoint() => _handler.Request.ShouldBeNull();
    [Fact] void should_not_issue_a_complete_attestation() => _attestationIssuer.Identity.ShouldBeNull();
    [Fact] void should_not_continue_the_pipeline() => _nextCalled.ShouldBeFalse();
    [Fact] void should_serve_the_email_unavailable_page() => _errorPageProvider.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.InvitationEmailUnavailable, StatusCodes.Status403Forbidden);
}
