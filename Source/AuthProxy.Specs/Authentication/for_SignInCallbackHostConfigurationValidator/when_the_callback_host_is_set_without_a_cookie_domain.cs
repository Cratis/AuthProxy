// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInCallbackHostConfigurationValidator;

public class when_the_callback_host_is_set_without_a_cookie_domain : given.a_callback_host_validator
{
    void Establish()
    {
        _config.Session.CookieDomain = string.Empty;
        CallbackHost("auth.example.test");
    }

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_ask_for_the_cookie_domain() => Reports("CookieDomain").ShouldBeTrue();
}
