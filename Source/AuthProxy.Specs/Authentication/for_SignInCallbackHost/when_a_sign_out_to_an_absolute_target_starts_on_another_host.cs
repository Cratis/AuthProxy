// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInCallbackHost;

public class when_a_sign_out_to_an_absolute_target_starts_on_another_host : given.a_proxy_on_one_of_its_hosts
{
    void Because() => BounceLogout("https://operations.example.test/");

    [Fact] void should_carry_the_target_unchanged() => QueryValue("redirect").ShouldEqual("https://operations.example.test/");
}
