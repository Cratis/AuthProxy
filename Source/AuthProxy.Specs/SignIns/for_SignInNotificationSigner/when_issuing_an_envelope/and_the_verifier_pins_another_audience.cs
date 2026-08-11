// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInNotificationSigner.given;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.SignIns.for_SignInNotificationSigner.when_issuing_an_envelope;

/// <summary>
/// The audience binding, mutated on its own: an envelope minted for one application cannot be presented to a
/// second one, which is what stops a shared AuthProxy deployment from cross-feeding sign-ins.
/// </summary>
public class and_the_verifier_pins_another_audience : a_sign_in_notification_signer
{
    TokenValidationResult _underAnotherAudience;
    TokenValidationResult _underTheConfiguredAudience;

    async Task Because()
    {
        _signer.TryIssue(HttpMethod.Post, Target, Body, out var envelope);
        _underAnotherAudience = await Validate(envelope, audience: "another-application");
        _underTheConfiguredAudience = await Validate(envelope);
    }

    [Fact] void should_reject_the_envelope() => _underAnotherAudience.IsValid.ShouldBeFalse();
    [Fact] void should_still_verify_for_the_configured_audience() => _underTheConfiguredAudience.IsValid.ShouldBeTrue();
}
