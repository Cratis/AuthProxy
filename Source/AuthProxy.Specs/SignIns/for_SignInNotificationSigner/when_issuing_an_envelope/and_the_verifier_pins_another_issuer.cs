// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInNotificationSigner.given;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.SignIns.for_SignInNotificationSigner.when_issuing_an_envelope;

/// <summary>
/// The provenance binding as the verifier reads it: an envelope claiming a different origin than the one the
/// application expects is refused, while the configured origin still passes.
/// </summary>
public class and_the_verifier_pins_another_issuer : a_sign_in_notification_signer
{
    TokenValidationResult _underAnotherIssuer;
    TokenValidationResult _underTheConfiguredIssuer;

    async Task Because()
    {
        _signer.TryIssue(HttpMethod.Post, Target, Body, out var envelope);
        _underAnotherIssuer = await Validate(envelope, issuer: "https://impostor.example.com");
        _underTheConfiguredIssuer = await Validate(envelope);
    }

    [Fact] void should_reject_the_envelope() => _underAnotherIssuer.IsValid.ShouldBeFalse();
    [Fact] void should_still_verify_under_the_configured_issuer() => _underTheConfiguredIssuer.IsValid.ShouldBeTrue();
}
