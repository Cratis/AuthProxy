// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites.for_InviteMiddleware.given;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware;

public class when_completing_an_identity_bound_attested_invitation : an_attested_invite_completion
{
    protected override bool InvitationCompletionEnabled => false;
    protected override bool InvitationIdentityBindingCompletionEnabled => true;
    protected override bool IncludeVerifiedEmailClaims => false;
    protected override IReadOnlyList<Claim> InvitationClaims =>
    [
        new(InvitationCapabilityClaims.RecipientProviderKey, "workforce"),
        new(InvitationCapabilityClaims.RecipientIdentityBinding, new string('A', 43)),
    ];

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_authenticate_the_downstream_call_with_the_complete_attestation() => _handler.Request!.Headers.Authorization!.Parameter.ShouldEqual("complete-attestation");
    [Fact] void should_attest_the_exact_bound_provider() => _attestationIssuer.Identity!.ProviderKey.ShouldEqual("workforce");
    [Fact] void should_attest_the_provider_subject() => _attestationIssuer.Identity!.ProviderSubject.ShouldEqual("provider-subject");
    [Fact] void should_attest_the_framework_validated_issuer() => _attestationIssuer.Identity!.ProviderIssuer.ShouldEqual("https://identity.example.com");
    [Fact] void should_not_invent_verified_email_evidence() => _attestationIssuer.Identity!.Email.ShouldBeNull();
    [Fact] void should_continue_only_after_success() => _nextCalled.ShouldBeTrue();
}
