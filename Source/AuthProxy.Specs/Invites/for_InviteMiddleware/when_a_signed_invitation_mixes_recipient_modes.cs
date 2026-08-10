// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites.for_InviteMiddleware.given;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware;

public class when_a_signed_invitation_mixes_recipient_modes : a_recipient_mode_capability
{
    bool _accepted;

    void Because() => _accepted = InviteMiddleware.TryResolveRecipientMode(
        Capability(
            new Claim("email", "invitee@example.com"),
            new Claim(InvitationCapabilityClaims.RecipientProviderKey, "microsoft"),
            new Claim(InvitationCapabilityClaims.RecipientIdentityBinding, new string('A', 43))),
        "email",
        out _);

    [Fact] void should_reject_the_capability() => _accepted.ShouldBeFalse();
}
