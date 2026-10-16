// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInReturnUrl;

public class when_an_absolute_url_is_on_the_callback_host : given.a_sign_in_request
{
    void Because() => Resolve("https://auth.example.test/welcome");

    [Fact] void should_keep_it() => _result.ShouldEqual("https://auth.example.test/welcome");
}
