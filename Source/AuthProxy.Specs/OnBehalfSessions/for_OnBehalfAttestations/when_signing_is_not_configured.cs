// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfAttestations.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfAttestations;

public class when_signing_is_not_configured : an_on_behalf_attestation_issuer
{
    bool _issued;
    string _token;

    void Because()
    {
        _configuration.Value.OnBehalf!.Attestation = null;
        _issued = _attestations.TryIssueForForward(_session, new OnBehalfForward("portal", HttpMethod.Get, "/"), "principal", "actor", out _token);
    }

    [Fact] void should_not_issue_anything() => _issued.ShouldBeFalse();
    [Fact] void should_not_hand_back_a_token() => _token.ShouldEqual(string.Empty);
}
