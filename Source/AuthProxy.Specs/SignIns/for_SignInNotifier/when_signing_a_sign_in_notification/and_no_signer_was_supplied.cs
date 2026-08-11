// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier.when_signing_a_sign_in_notification;

/// <summary>
/// The released constructors are still available for direct construction, and they carry no signer. A caller
/// that builds the notifier that way while the deployment asks for signed notifications gets no notification
/// rather than an unauthenticated one.
/// </summary>
public class and_no_signer_was_supplied : a_signed_sign_in_notifier
{
    protected override bool SignerIsAvailable => false;

    SignInNotificationResult _result;

    async Task Because() => _result = await _notifier.Notify(_httpContext, _principal);

    [Fact] void should_report_the_notification_as_failed() => _result.ShouldEqual(SignInNotificationResult.Failed);
    [Fact] void should_not_post_anything_at_all() => _handler.LastRequest.ShouldBeNull();
}
