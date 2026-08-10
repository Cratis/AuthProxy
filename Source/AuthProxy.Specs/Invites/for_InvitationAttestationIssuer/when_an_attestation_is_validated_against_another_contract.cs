// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Cratis.AuthProxy.Invites.for_InvitationAttestationIssuer.given;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Invites.for_InvitationAttestationIssuer;

public class when_an_attestation_is_validated_against_another_contract : an_attestation_issuer
{
    TokenValidationResult _wrongAudience;
    TokenValidationResult _wrongIssuer;
    TokenValidationResult _wrongKey;
    TokenValidationResult _tampered;

    async Task Because()
    {
        _issuer.TryIssueStage(_state, out var attestation);
        using var rsa = RSA.Create(2048);
        var wrongKey = new RsaSecurityKey(rsa.ExportParameters(false));
        _wrongAudience = await Validate(attestation, audience: "another-audience");
        _wrongIssuer = await Validate(attestation, issuer: "https://another-issuer.example.com");
        _wrongKey = await Validate(attestation, wrongKey);
        var replacement = attestation[^1] == 'A' ? 'B' : 'A';
        _tampered = await Validate($"{attestation[..^1]}{replacement}");
    }

    [Fact] void should_reject_the_wrong_audience() => _wrongAudience.IsValid.ShouldBeFalse();
    [Fact] void should_reject_the_wrong_issuer() => _wrongIssuer.IsValid.ShouldBeFalse();
    [Fact] void should_reject_the_wrong_key() => _wrongKey.IsValid.ShouldBeFalse();
    [Fact] void should_reject_a_tampered_attestation() => _tampered.IsValid.ShouldBeFalse();
}
