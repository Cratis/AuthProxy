// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInReturnUrl;

public class when_an_absolute_url_is_on_a_declared_host_spelled_in_another_case : given.a_sign_in_request
{
    void Because() => Resolve("https://CONSOLE.Example.Test/Dashboard");

    [Fact] void should_keep_the_origin_in_the_spelling_given() => _result.ToLowerInvariant().ShouldEqual("https://console.example.test/dashboard");
}
