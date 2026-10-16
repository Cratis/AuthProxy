// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInCallbackHost;

public class when_a_sign_out_starts_on_another_host : given.a_proxy_on_one_of_its_hosts
{
    void Because() => BounceLogout("/goodbye");

    [Fact] void should_bounce() => _bounced.ShouldBeTrue();
    [Fact] void should_go_to_the_logout_endpoint_of_the_callback_host() => _location.StartsWith("https://auth.example.test/.cratis/logout?", StringComparison.Ordinal).ShouldBeTrue();
    [Fact] void should_carry_the_destination_as_an_address_on_the_original_host() => QueryValue("redirect").ShouldEqual("https://console.example.test/goodbye");
}
