// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInReturnUrl;

public class when_a_callback_host_is_configured_without_a_cookie_domain : given.a_sign_in_request
{
    void Establish() => _config.Session.CookieDomain = string.Empty;

    void Because() => Resolve("https://console.example.test/dashboard");

    [Fact] void should_not_keep_the_origin_because_the_session_would_not_follow() => _result.ShouldEqual("/dashboard");
}
