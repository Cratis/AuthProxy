// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInCallbackHost;

public class when_a_sign_in_starts_on_another_host_with_a_hostile_return_url : given.a_proxy_on_one_of_its_hosts
{
    void Because() => BounceLogin("https://evil.test/phish");

    [Fact] void should_still_bounce_to_the_configured_host_only() => _location.StartsWith("https://auth.example.test/.cratis/login/github?", StringComparison.Ordinal).ShouldBeTrue();
    [Fact] void should_carry_the_reduced_path_on_the_original_host() => QueryValue("returnUrl").ShouldEqual("https://console.example.test/phish");
}
