// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier;

public class when_notifying_a_completed_sign_in : a_sign_in_notifier
{
    SignInNotificationResult _result;

    async Task Because() => _result = await _notifier.Notify(_httpContext, _principal);

    [Fact] void should_notify() => _result.ShouldEqual(SignInNotificationResult.Notified);
    [Fact] void should_post_to_the_configured_notify_url() => _handler.LastRequest!.RequestUri!.ToString().ShouldEqual(NotifyUrl);
    [Fact] void should_post() => _handler.LastRequest!.Method.ShouldEqual(HttpMethod.Post);
    [Fact] void should_send_the_subject() => _handler.LastRequestBody!.ShouldContain("subject-123");
    [Fact] void should_send_the_identity_provider() => _handler.LastRequestBody!.ShouldContain("https://github.com");
    [Fact] void should_send_the_client_ip_from_the_forwarded_header() => _handler.LastRequestBody!.ShouldContain("203.0.113.7");
    [Fact] void should_send_the_approximate_location() => _handler.LastRequestBody!.ShouldContain("Oslo");
    [Fact] void should_send_the_parsed_browser() => _handler.LastRequestBody!.ShouldContain("Chrome");
    [Fact] void should_send_the_parsed_operating_system() => _handler.LastRequestBody!.ShouldContain("Windows");
}
