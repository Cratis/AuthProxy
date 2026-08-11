// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites.for_InvitationAttestationIssuer.given;

namespace Cratis.AuthProxy.Invites.for_InvitationAttestationIssuer;

/// <summary>
/// Startup validation should never let this configuration through, but resolving the active key sits on the
/// request path — so a duplicate identifier that did get through has to degrade to a refusal to issue, not to
/// an exception thrown at whoever is holding the invitation link.
/// </summary>
public class when_the_active_key_identifier_is_duplicated : an_attestation_issuer
{
    bool _issued;
    string _attestation;
    Exception _error;

    void Establish() =>
        _configuration.Invite!.Attestation!.SigningKeys.Add(new C.InvitationAttestationSigningKey
        {
            KeyId = KeyId,
            PrivateKeyPem = _configuration.Invite.Attestation.SigningKeys[0].PrivateKeyPem,
        });

    void Because() => _error = Catch.Exception(() => _issued = _issuer.TryIssueStage(_state, out _attestation));

    [Fact] void should_not_throw_out_of_the_request() => _error.ShouldBeNull();
    [Fact] void should_still_issue_the_attestation() => _issued.ShouldBeTrue();
}
