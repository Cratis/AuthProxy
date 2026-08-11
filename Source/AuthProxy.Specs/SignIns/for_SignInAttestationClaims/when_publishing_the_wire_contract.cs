// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.SignIns.for_SignInAttestationClaims;

/// <summary>
/// Pins the published wire contract to literals rather than to the constants that produce it.
/// </summary>
/// <remarks>
/// Every other assertion in the suite reads a constant and compares it to the same constant, so renaming one
/// would leave all of them green while every deployed verifier broke — the claim names and the purpose value
/// are a contract with software AuthProxy does not build. These literals are what makes such a rename fail
/// here instead of in production. The separation assertions do the same for the collision the shape of
/// <see cref="InvitationAttestationClaims"/> otherwise makes invisible: both protocols sign a <c>purpose</c>
/// claim with the same key material, so two purposes that ever converged would let one protocol's assertion be
/// replayed as the other's.
/// </remarks>
public class when_publishing_the_wire_contract : Specification
{
    [Fact] void should_publish_the_method_claim_as_the_rfc_9449_htm() => SignInAttestationClaims.HttpMethod.ShouldEqual("htm");
    [Fact] void should_publish_the_target_claim_as_the_rfc_9449_htu() => SignInAttestationClaims.HttpUri.ShouldEqual("htu");
    [Fact] void should_publish_the_body_digest_claim_as_body_hash() => SignInAttestationClaims.BodyHash.ShouldEqual("body_hash");
    [Fact] void should_publish_the_separating_claim_as_purpose() => SignInAttestationClaims.Purpose.ShouldEqual("purpose");
    [Fact] void should_publish_the_notification_purpose_value() => SignInAttestationClaims.NotificationPurpose.ShouldEqual("sign-in-notification");
    [Fact] void should_separate_the_notification_from_invitation_staging() => SignInAttestationClaims.NotificationPurpose.ShouldNotEqual(InvitationAttestationClaims.StagePurpose);
    [Fact] void should_separate_the_notification_from_invitation_completion() => SignInAttestationClaims.NotificationPurpose.ShouldNotEqual(InvitationAttestationClaims.CompletePurpose);
    [Fact] void should_share_the_separating_claim_name_with_every_other_signed_protocol() => SignInAttestationClaims.Purpose.ShouldEqual(InvitationAttestationClaims.Purpose);
}
