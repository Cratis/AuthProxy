// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites.for_InviteMiddleware.given;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware;

public class when_completing_an_attested_invitation : an_attested_invite_completion
{
    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_authenticate_the_downstream_call_with_the_complete_attestation() => _handler.Request!.Headers.Authorization!.Parameter.ShouldEqual("complete-attestation");
    [Fact] void should_send_only_the_transaction_in_the_body() => _handler.Body.ShouldEqual($"{{\"invitationTransaction\":\"{Transaction}\"}}");
    [Fact] void should_not_allow_the_body_to_author_the_provider() => _handler.Body.ShouldNotContain("provider");
    [Fact] void should_not_allow_the_body_to_author_the_email() => _handler.Body.ShouldNotContain("email");
    [Fact] void should_attest_the_canonical_provider_key() => _attestationIssuer.Identity!.ProviderKey.ShouldEqual("workforce");
    [Fact] void should_attest_the_canonical_provider_issuer() => _attestationIssuer.Identity!.ProviderIssuer.ShouldEqual("https://identity.example.com");
    [Fact] void should_attest_the_canonical_provider_subject() => _attestationIssuer.Identity!.ProviderSubject.ShouldEqual("provider-subject");
    [Fact] void should_attest_the_verified_provider_email() => _attestationIssuer.Identity!.Email.ShouldEqual(Email);
    [Fact] void should_attest_provider_assurance() => _attestationIssuer.Identity!.Assurance.ShouldEqual("mfa");
    [Fact] void should_continue_only_after_success() => _nextCalled.ShouldBeTrue();
}
