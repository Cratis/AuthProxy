// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites.for_InviteMiddleware.given;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware;

public class when_completing_an_attested_invitation_without_verified_email : an_attested_invite_completion
{
    async Task Because()
    {
        var identity = (ClaimsIdentity)_context.User.Identity!;
        foreach (var claim in identity.Claims.Where(_ =>
                     string.Equals(_.Type, "email", StringComparison.Ordinal)
                     || string.Equals(_.Type, "email_verified", StringComparison.Ordinal)).ToArray())
        {
            identity.RemoveClaim(claim);
        }

        await _middleware.InvokeAsync(_context);
    }

    [Fact] void should_not_call_the_completion_endpoint() => _handler.Request.ShouldBeNull();
    [Fact] void should_not_issue_a_complete_attestation() => _attestationIssuer.Identity.ShouldBeNull();
    [Fact] void should_not_continue_the_pipeline() => _nextCalled.ShouldBeFalse();

    /// <summary>
    /// The identity provider supplied no usable email at all, so the invitee sees the dedicated
    /// unavailable-address outcome instead of a generic invalid-link denial that offers no real recovery.
    /// </summary>
    [Fact] void should_serve_the_email_unavailable_page() => _errorPageProvider.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.InvitationEmailUnavailable, StatusCodes.Status403Forbidden);
}
