// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier;

public class when_the_notify_url_is_not_configured : a_sign_in_notifier
{
    SignInNotificationResult _result;

    protected override C.AuthProxy CreateConfig() => new() { SignIn = null };

    async Task Because() => _result = await _notifier.Notify(_httpContext, _principal);

    [Fact] void should_skip() => _result.ShouldEqual(SignInNotificationResult.Skipped);
    [Fact] void should_not_post_anything() => _handler.LastRequest.ShouldBeNull();
}
