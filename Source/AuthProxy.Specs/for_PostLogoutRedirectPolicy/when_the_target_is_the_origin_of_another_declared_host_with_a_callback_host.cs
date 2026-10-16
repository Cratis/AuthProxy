// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_PostLogoutRedirectPolicy;

public class when_the_target_is_the_origin_of_another_declared_host_with_a_callback_host : given.a_logout_request
{
    void Establish()
    {
        _config.Session.CookieDomain = ".example.test";
        _config.SignIn = new() { CallbackHost = "auth.example.test" };
    }

    void Because() => Check("https://operations.example.test/goodbye");

    [Fact] void should_allow_it() => _allowed.ShouldBeTrue();
}
