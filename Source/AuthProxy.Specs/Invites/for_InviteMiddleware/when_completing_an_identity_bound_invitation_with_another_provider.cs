// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites.for_InviteMiddleware.given;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware;

public class when_completing_an_identity_bound_invitation_with_another_provider : an_attested_invite_completion
{
    protected override bool InvitationCompletionEnabled => false;
    protected override bool InvitationIdentityBindingCompletionEnabled => true;
    protected override bool IncludeVerifiedEmailClaims => false;
    protected override IReadOnlyList<Claim> InvitationClaims =>
    [
        new(InvitationCapabilityClaims.RecipientProviderKey, "different-workforce"),
        new(InvitationCapabilityClaims.RecipientIdentityBinding, new string('A', 43)),
    ];

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_call_the_completion_endpoint() => _handler.Request.ShouldBeNull();
    [Fact] void should_not_issue_a_complete_attestation() => _attestationIssuer.Identity.ShouldBeNull();
    [Fact] void should_not_continue_the_pipeline() => _nextCalled.ShouldBeFalse();
    [Fact] void should_serve_a_branded_denial() => _errorPageProvider.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.InvitationInvalid, StatusCodes.Status403Forbidden);
}
