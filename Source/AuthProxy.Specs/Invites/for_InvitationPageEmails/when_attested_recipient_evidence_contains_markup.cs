// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationPageEmails;

public class when_attested_recipient_evidence_contains_markup : for_InviteMiddleware.given.an_attested_invite_completion
{
    protected override IReadOnlyList<Claim> InvitationClaims => [new(InvitationAttestationClaims.Email, "<script>invite</script>@example.com")];

    Task Because() => _middleware.InvokeAsync(_context);

    [Fact] void should_encode_the_captured_recipient_and_supply_the_asserted_address() => _errorPageProvider.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.InvitationEmailMismatch, StatusCodes.Status403Forbidden, Arg.Is<IReadOnlyDictionary<string, string>>(values => values["{{invitedEmail}}"] == "&lt;script&gt;invite&lt;/script&gt;@example.com" && values["{{assertedEmail}}"] == Email));
    [Fact] void should_issue_no_completion_attestation() => _attestationIssuer.Identity.ShouldBeNull();
}
