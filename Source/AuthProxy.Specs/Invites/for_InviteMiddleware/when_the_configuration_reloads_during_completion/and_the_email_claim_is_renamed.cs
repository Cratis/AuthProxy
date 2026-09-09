// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_the_configuration_reloads_during_completion;

/// <summary>
/// The invited-email claim type is renamed while the completion is awaiting the session, so the capability
/// no longer carries a claim of the configured type at all. The person completing the invitation is its
/// actual recipient, and stays it: the recipient was captured with the entry state before the reload, so the
/// completion still binds to the address the invitation was issued for.
/// </summary>
/// <remarks>
/// This is the positive pole of this folder. A fix that simply refused everything after a reload would pass
/// the refusal specifications here and fail this one.
/// </remarks>
public class and_the_email_claim_is_renamed : given.an_attested_invite_completion
{
    protected override string? ReloadedEmailClaimDuringSession => "renamed_invited_email";

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_attest_the_captured_invited_recipient() => _attestationIssuer.Identity!.Email.ShouldEqual(Email);
    [Fact] void should_attest_the_canonical_provider_subject() => _attestationIssuer.Identity!.ProviderSubject.ShouldEqual("provider-subject");
    [Fact] void should_call_the_completion_endpoint() => _handler.Request.ShouldNotBeNull();
    [Fact] void should_continue_only_after_success() => _nextCalled.ShouldBeTrue();
}
