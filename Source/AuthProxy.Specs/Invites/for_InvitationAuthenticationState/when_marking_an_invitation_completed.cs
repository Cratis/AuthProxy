// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Invites.for_InvitationAuthenticationState;

/// <summary>
/// Completing an invitation replaces the pending capability binding with the completion record: the session
/// stops claiming to have been established <em>for</em> the invitation — that claim would re-run the
/// exchange the moment a stale pending cookie replays — and instead carries proof it already completed it.
/// </summary>
public class when_marking_an_invitation_completed : Specification
{
    const string Capability = "completed-capability";

    AuthenticationProperties _properties;

    void Establish()
    {
        _properties = new AuthenticationProperties();
        _properties.Items[InvitationAuthenticationState.TransactionStateKey] = "transaction";
        _properties.Items[InvitationAuthenticationState.ChallengeStateKey] = "challenge";
        InvitationAuthenticationState.BindCapability(_properties, Capability);
    }

    void Because() => InvitationAuthenticationState.MarkCompleted(_properties, Capability);

    [Fact]
    void should_record_the_completed_capability() =>
        _properties.Items[InvitationAuthenticationState.CompletedCapabilityHashStateKey]
            .ShouldEqual(InvitationAuthenticationState.ComputeCapabilityHash(Capability));

    [Fact]
    void should_no_longer_claim_the_session_was_established_for_the_invitation() =>
        InvitationAuthenticationState.WasEstablishedFor(_properties, Capability).ShouldBeFalse();

    [Fact]
    void should_remove_the_transaction() =>
        _properties.Items.ContainsKey(InvitationAuthenticationState.TransactionStateKey).ShouldBeFalse();

    [Fact]
    void should_remove_the_challenge() =>
        _properties.Items.ContainsKey(InvitationAuthenticationState.ChallengeStateKey).ShouldBeFalse();

    [Fact]
    void should_answer_completed_for_the_exact_capability() =>
        InvitationAuthenticationState.WasCompletedFor(_properties, Capability).ShouldBeTrue();

    [Fact]
    void should_not_answer_completed_for_another_capability() =>
        InvitationAuthenticationState.WasCompletedFor(_properties, "another-capability").ShouldBeFalse();

    [Fact]
    void should_not_answer_completed_for_a_session_without_the_record() =>
        InvitationAuthenticationState.WasCompletedFor(new AuthenticationProperties(), Capability).ShouldBeFalse();
}
