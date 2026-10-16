// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInCallbackHost;

public class when_a_sign_in_starts_on_another_host : given.a_proxy_on_one_of_its_hosts
{
    void Because() => BounceLogin("/dashboard?tab=2");

    [Fact] void should_bounce() => _bounced.ShouldBeTrue();
    [Fact] void should_go_to_the_login_endpoint_of_the_callback_host() => _location.StartsWith("https://auth.example.test/.cratis/login/github?", StringComparison.Ordinal).ShouldBeTrue();
    [Fact] void should_carry_the_original_address_with_path_and_query() => QueryValue("returnUrl").ShouldEqual("https://console.example.test/dashboard?tab=2");
    [Fact] void should_mark_the_request_as_bounced() => QueryValue(SignInCallbackHost.BouncedQueryKey).ShouldEqual("1");
}
