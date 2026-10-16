// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInReturnUrl;

public class when_an_absolute_url_is_on_a_declared_host : given.a_sign_in_request
{
    void Because() => Resolve("https://console.example.test/dashboard?tab=2#section");

    [Fact] void should_keep_the_origin_path_and_query() => _result.ShouldEqual("https://console.example.test/dashboard?tab=2");
}
