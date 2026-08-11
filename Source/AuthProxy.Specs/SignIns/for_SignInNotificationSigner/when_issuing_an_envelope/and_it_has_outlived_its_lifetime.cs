// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInNotificationSigner.given;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.SignIns.for_SignInNotificationSigner.when_issuing_an_envelope;

/// <summary>
/// The time binding, mutated on its own: an envelope captured and presented after its configured lifetime is
/// refused, while the very same envelope verifies for a receiver whose clock still sits inside that window.
/// </summary>
public class and_it_has_outlived_its_lifetime : a_sign_in_notification_signer
{
    protected override DateTimeOffset IssuedAt => _now.AddMinutes(-5);

    TokenValidationResult _afterExpiry;
    TokenValidationResult _withinTheWindow;

    async Task Because()
    {
        _signer.TryIssue(HttpMethod.Post, Target, Body, out var envelope);
        _afterExpiry = await Validate(envelope);
        _withinTheWindow = await Validate(envelope, clockSkew: TimeSpan.FromMinutes(30));
    }

    [Fact] void should_reject_the_expired_envelope() => _afterExpiry.IsValid.ShouldBeFalse();
    [Fact] void should_have_been_a_valid_envelope_inside_its_window() => _withinTheWindow.IsValid.ShouldBeTrue();
}
