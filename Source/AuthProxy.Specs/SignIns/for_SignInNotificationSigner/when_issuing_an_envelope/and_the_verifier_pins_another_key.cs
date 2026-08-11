// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInNotificationSigner.given;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.SignIns.for_SignInNotificationSigner.when_issuing_an_envelope;

/// <summary>
/// The provenance binding, mutated on its own: an application that pins a key AuthProxy does not hold must
/// reject the envelope, and the same envelope must still verify under the real key so the rejection cannot be
/// green merely because nothing was signed.
/// </summary>
public class and_the_verifier_pins_another_key : a_sign_in_notification_signer
{
    TokenValidationResult _underTheUnrelatedKey;
    TokenValidationResult _underTheRealKey;

    async Task Because()
    {
        _signer.TryIssue(HttpMethod.Post, Target, Body, out var envelope);
        _underTheUnrelatedKey = await Validate(envelope, _unrelatedKey);
        _underTheRealKey = await Validate(envelope);
    }

    [Fact] void should_reject_the_envelope() => _underTheUnrelatedKey.IsValid.ShouldBeFalse();
    [Fact] void should_still_verify_under_the_real_key() => _underTheRealKey.IsValid.ShouldBeTrue();
}
