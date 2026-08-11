// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier.when_signing_a_sign_in_notification;

/// <summary>
/// Once a deployment has asked for signed notifications, an unsigned one is never an acceptable fallback.
/// Unusable key material must cost the notification, not its authentication — otherwise a deployer who
/// mounted a secret wrong would silently be back on the unauthenticated back-channel this exists to close.
/// </summary>
public class and_the_envelope_cannot_be_signed : a_signed_sign_in_notifier
{
    protected override string ConfiguredSigningKeyPem => "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----";

    SignInNotificationResult _result;

    async Task Because() => _result = await _notifier.Notify(_httpContext, _principal);

    [Fact] void should_report_the_notification_as_failed() => _result.ShouldEqual(SignInNotificationResult.Failed);
    [Fact] void should_not_post_anything_at_all() => _handler.LastRequest.ShouldBeNull();
}
