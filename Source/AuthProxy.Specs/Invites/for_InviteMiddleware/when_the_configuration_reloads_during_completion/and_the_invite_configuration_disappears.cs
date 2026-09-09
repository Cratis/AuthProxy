// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_the_configuration_reloads_during_completion;

/// <summary>
/// The whole invite configuration is withdrawn while the completion is awaiting the session, and the
/// identity provider flagged the account's address as unverified. Neither fact may produce an attestation:
/// the invitation's recipient was captured before the reload, and unverified provider evidence never
/// satisfies it.
/// </summary>
public class and_the_invite_configuration_disappears : given.an_attested_invite_completion
{
    protected override bool RemovesInviteDuringSession => true;

    async Task Because()
    {
        var identity = (ClaimsIdentity)_context.User.Identity!;
        identity.RemoveClaim(identity.FindFirst("email_verified"));
        identity.AddClaim(new Claim("email_verified", bool.FalseString.ToLowerInvariant()));

        await _middleware.InvokeAsync(_context);
    }

    [Fact] void should_not_issue_a_complete_attestation() => _attestationIssuer.Identity.ShouldBeNull();
    [Fact] void should_not_call_the_completion_endpoint() => _handler.Request.ShouldBeNull();
    [Fact] void should_not_continue_the_pipeline() => _nextCalled.ShouldBeFalse();
    [Fact] void should_serve_the_email_mismatch_page() => _errorPageProvider.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.InvitationEmailMismatch, StatusCodes.Status403Forbidden);
}
