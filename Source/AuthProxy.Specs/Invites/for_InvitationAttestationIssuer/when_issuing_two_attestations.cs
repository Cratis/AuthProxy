// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites.for_InvitationAttestationIssuer.given;

namespace Cratis.AuthProxy.Invites.for_InvitationAttestationIssuer;

public class when_issuing_two_attestations : an_attestation_issuer
{
    string _firstIdentifier;
    string _secondIdentifier;

    void Because()
    {
        _issuer.TryIssueStage(_state, out var first);
        _issuer.TryIssueStage(_state, out var second);
        _firstIdentifier = Read(first).Id;
        _secondIdentifier = Read(second).Id;
    }

    [Fact] void should_use_a_new_identifier_for_every_attestation() => (_secondIdentifier == _firstIdentifier).ShouldBeFalse();
}
