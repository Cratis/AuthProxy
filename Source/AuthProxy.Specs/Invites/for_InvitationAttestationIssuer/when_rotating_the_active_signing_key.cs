// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Cratis.AuthProxy.Invites.for_InvitationAttestationIssuer.given;

namespace Cratis.AuthProxy.Invites.for_InvitationAttestationIssuer;

public class when_rotating_the_active_signing_key : an_attestation_issuer
{
    const string NewKeyId = "invite-2026-09";
    string _tokenKeyId;

    void Because()
    {
        using var rsa = RSA.Create(2048);
        _configuration.Invite!.Attestation!.SigningKeys.Add(new C.InvitationAttestationSigningKey
        {
            KeyId = NewKeyId,
            PrivateKeyPem = rsa.ExportPkcs8PrivateKeyPem(),
        });
        _configuration.Invite.Attestation.ActiveKeyId = NewKeyId;
        _issuer.TryIssueStage(_state, out var attestation);
        _tokenKeyId = Read(attestation).Kid;
    }

    [Fact] void should_sign_with_the_new_active_key() => _tokenKeyId.ShouldEqual(NewKeyId);
}
